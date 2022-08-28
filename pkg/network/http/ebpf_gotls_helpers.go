package http

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"reflect"
)

func inspectionResultToProbeData(result *bininspect.Result) (ebpf.TlsProbeData, error) {
	readConnPointer, err := getconnPointer(result, bininspect.ReadGoTLSFunc)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting read conn pointer from inspection result: %w", err)
	}
	writeConnPointer, err := getconnPointer(result, bininspect.WriteGoTLSFunc)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting write conn pointer from inspection result: %w", err)
	}
	closeConnPointer, err := getconnPointer(result, bininspect.CloseGoTLSFunc)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting close conn pointer from inspection result: %w", err)
	}
	readBufferLocation, err := getReadBufferLocation(result)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting read buffer location from inspection result: %w", err)
	}
	writeBufferLocation, err := getWriteBufferLocation(result)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting write buffer location from inspection result: %w", err)
	}
	readReturnBytes, err := getReadReturnBytes(result)
	if err != nil {
		return ebpf.TlsProbeData{}, fmt.Errorf("failed extracting read return bytes from inspection result: %w", err)
	}

	return ebpf.TlsProbeData{
		Goroutine_id: ebpf.GoroutineIDMetadata{
			Runtime_g_tls_addr_offset: result.GoroutineIDMetadata.RuntimeGTLSAddrOffset,
			Goroutine_id_offset:       result.GoroutineIDMetadata.GoroutineIDOffset,
			Runtime_g_register:        int64(result.GoroutineIDMetadata.RuntimeGRegister),
			Runtime_g_in_register:     boolToBinary(result.GoroutineIDMetadata.RuntimeGInRegister),
		},
		Conn_layout: ebpf.TlsConnLayout{
			Tls_conn_inner_conn_offset: result.StructOffsets[bininspect.StructOffsetTLSConn],
			Tcp_conn_inner_conn_offset: result.StructOffsets[bininspect.StructOffsetTCPConn],
			Conn_fd_offset:             result.StructOffsets[bininspect.StructOffsetNetConnFd],
			Net_fd_pfd_offset:          result.StructOffsets[bininspect.StructOffsetNetFdPfd],
			Fd_sysfd_offset:            result.StructOffsets[bininspect.StructOffsetPollFdSysfd],
		},
		Read_conn_pointer:  readConnPointer,
		Read_buffer:        readBufferLocation,
		Read_return_bytes:  readReturnBytes,
		Write_conn_pointer: writeConnPointer,
		Write_buffer:       writeBufferLocation,
		Close_conn_pointer: closeConnPointer,
	}, nil
}

func getconnPointer(result *bininspect.Result, funcName string) (ebpf.Location, error) {
	readConnReceiver := result.Functions[funcName].Parameters[0]
	return wordLocation(readConnReceiver, result.Arch, "pointer", reflect.Ptr)
}

func getReadBufferLocation(result *bininspect.Result) (ebpf.SliceLocation, error) {
	bufferParam := result.Functions[bininspect.ReadGoTLSFunc].Parameters[1]
	if result.GoVersion.Major == 1 && result.GoVersion.Minor == 16 && len(bufferParam.Pieces) == 0 {
		return ebpf.SliceLocation{
			Ptr: ebpf.Location{
				Exists:       boolToBinary(true),
				In_register:  boolToBinary(false),
				Stack_offset: 16,
			},
			Len: ebpf.Location{
				Exists:       boolToBinary(true),
				In_register:  boolToBinary(false),
				Stack_offset: 24,
			},
			Cap: ebpf.Location{
				Exists:       boolToBinary(true),
				In_register:  boolToBinary(false),
				Stack_offset: 32,
			},
		}, nil
	}
	return sliceLocation(bufferParam, result.Arch)
}

func getWriteBufferLocation(result *bininspect.Result) (ebpf.SliceLocation, error) {
	bufferParam := result.Functions[bininspect.WriteGoTLSFunc].Parameters[1]
	return sliceLocation(bufferParam, result.Arch)
}

func getReadReturnBytes(result *bininspect.Result) (ebpf.Location, error) {
	// Manually re-consturct the location of the first return parameter (bytes read).
	// Unpack the first return parameter (bytes read).
	// The error return value isn't useful in eBPF
	// unless we can determine whether it is equal to io.EOF,
	// and I didn't find a straightforward way of doing this.
	//
	// Additionally, because the DWARF location lists return locations for the return values,
	// we're forced to manually determine their locations
	// by re-implementing the register allocation/stack layout algorithms
	// from the ABI specs.
	// As such, this region of code is especially sensitive to ABI changes.
	switch result.ABI {
	case bininspect.GoABIRegister:
		// Manually assign the registers.
		// This is fairly finnicky, but is simple
		// since the return arguments are short and are word-aligned
		var regOrder []int
		switch result.Arch {
		case bininspect.GoArchX86_64:
			// The order registers is assigned is in the below slice
			// (where each value is the register number):
			// From https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md
			// RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11
			regOrder = []int{0, 3, 2, 5, 4, 8, 9, 10, 11}
		case bininspect.GoArchARM64:
			// TODO implement
			return ebpf.Location{}, fmt.Errorf("ARM-64 register ABI fallback not implemented")
		}

		curReg := 0
		getNextReg := func() int {
			nextReg := regOrder[curReg]
			curReg += 1
			return nextReg
		}

		return ebpf.Location{
			Exists:      boolToBinary(true),
			In_register: boolToBinary(true),
			X_register:  int64(getNextReg()),
		}, nil
	case bininspect.GoABIStack:
		// Manually reconstruct the offsets into the stack.
		// Assume the return parameters exist on the stack in the stable struct,
		// adjacent to the parameters.
		// This is valid for go running ABI0/the stack ABI).
		// See:
		// - https://go.googlesource.com/proposal/+/refs/changes/78/248178/1/design/40724-register-calling.md#go_s-current-stack_based-abi
		// - https://dr-knz.net/go-calling-convention-x86-64-2020.html
		var endOfParametersOffset int64
		for _, param := range result.Functions[bininspect.ReadGoTLSFunc].Parameters {
			// This code assumes pointer alignment of each param
			endOfParametersOffset += param.TotalSize
		}

		currentOffset := endOfParametersOffset
		return ebpf.Location{
			Exists:       boolToBinary(true),
			In_register:  boolToBinary(false),
			Stack_offset: currentOffset,
		}, nil
	default:
		return ebpf.Location{}, fmt.Errorf("unknoen abi %q", result.ABI)
	}

}

func makeReturnUID(uid string, returnNumber int) string {
	return fmt.Sprintf("%s_%x", uid, returnNumber)
}

func boolToBinary(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func wordLocation(
	param bininspect.ParameterMetadata,
	arch bininspect.GoArch,
	typeName string,
	expectedKind reflect.Kind,
) (ebpf.Location, error) {
	if len(param.Pieces) == 0 {
		return ebpf.Location{Exists: boolToBinary(false)}, nil
	}

	if len(param.Pieces) != 1 {
		return ebpf.Location{}, fmt.Errorf("expected 1 piece for %s parameter, got %d", typeName, len(param.Pieces))
	}
	if param.Kind != expectedKind {
		return ebpf.Location{}, fmt.Errorf("expected %#v kind for %s parameter, got %#v", expectedKind, typeName, param.Kind)
	}
	if param.TotalSize != int64(arch.PointerSize()) {
		return ebpf.Location{}, fmt.Errorf("expected total size for %s parameter to be %d, got %d", typeName, arch.PointerSize(), param.TotalSize)
	}

	piece := param.Pieces[0]
	return ebpf.Location{
		Exists:       boolToBinary(true),
		In_register:  boolToBinary(piece.InReg),
		Stack_offset: piece.StackOffset,
		X_register:   int64(piece.Register),
	}, nil
}

func compositeLocation(
	param bininspect.ParameterMetadata,
	arch bininspect.GoArch,
	typeName string,
	expectedKind reflect.Kind,
	expectedPieces int,
) ([]ebpf.Location, error) {
	if len(param.Pieces) == 0 {
		locations := make([]ebpf.Location, expectedPieces)
		for i := range locations {
			locations[i] = ebpf.Location{
				Exists: boolToBinary(false),
			}
		}
		return locations, nil
	}

	if len(param.Pieces) < 1 || len(param.Pieces) > expectedPieces {
		return nil, fmt.Errorf("expected 1-%d pieces for %s parameter, got %d", expectedPieces, typeName, len(param.Pieces))
	}
	if param.Kind != expectedKind {
		return nil, fmt.Errorf("expected %#v kind for %s parameter, got %#v", expectedKind, typeName, param.Kind)
	}
	expectedSize := int64(int(arch.PointerSize()) * expectedPieces)
	if param.TotalSize != expectedSize {
		return nil, fmt.Errorf("expected total size for %s parameter to be %d, got %d", typeName, expectedSize, param.TotalSize)
	}

	// Translate the parameter pieces to a list of single word locations
	// TODO handle missing inner parts
	//      like the length (seems to handle missing cap)
	locations := make([]ebpf.Location, expectedPieces)
	currentLocation := 0
	for i, paramPiece := range param.Pieces {
		if paramPiece.InReg {
			if paramPiece.Size > int64(arch.PointerSize()) {
				return nil, fmt.Errorf("piece %d in %s parameter was in register but longer than %d bytes", i, typeName, arch.PointerSize())
			}

			locations[currentLocation] = ebpf.Location{
				Exists:      boolToBinary(true),
				In_register: boolToBinary(true),
				X_register:  int64(paramPiece.Register),
			}
			currentLocation += 1
		} else {
			// If the parameter piece is longer than a word,
			// divide it into multiple single-word locations
			var currentOffset int64
			remainingLength := paramPiece.Size
			for remainingLength > 0 {
				locations[currentLocation] = ebpf.Location{
					Exists:       boolToBinary(true),
					In_register:  boolToBinary(false),
					Stack_offset: paramPiece.StackOffset + currentOffset,
				}
				currentLocation += 1
				currentOffset += int64(arch.PointerSize())
				if remainingLength >= int64(arch.PointerSize()) {
					remainingLength -= int64(arch.PointerSize())
				} else {
					remainingLength = 0
				}
			}
		}
	}

	// Handle any trailing locations that don't exist
	if currentLocation != expectedPieces-1 {
		for ; currentLocation < expectedPieces; currentLocation++ {
			locations[expectedPieces] = ebpf.Location{
				Exists: boolToBinary(false),
			}
		}
	}

	return locations, nil
}

func sliceLocation(param bininspect.ParameterMetadata, arch bininspect.GoArch) (ebpf.SliceLocation, error) {
	locations, err := compositeLocation(param, arch, "slice", reflect.Slice, 3)
	if err != nil {
		return ebpf.SliceLocation{}, err
	}

	return ebpf.SliceLocation{
		Ptr: locations[0],
		Len: locations[1],
		Cap: locations[2],
	}, nil
}
