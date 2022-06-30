// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

//go:generate go run github.com/tinylib/msgp -o=activity_dump_graph_gen_linux.go -tests=false

package probe

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/DataDog/datadog-agent/pkg/security/probe/dump"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

var (
	processColor         = "#8fbbff"
	processRuntimeColor  = "#edf3ff"
	processSnapshotColor = "white"
	processShape         = "record"

	fileColor         = "#77bf77"
	fileRuntimeColor  = "#e9f3e7"
	fileSnapshotColor = "white"
	fileShape         = "record"

	dnsColor        = "#ff9800"
	dnsRuntimeColor = "#ffebcd"
	dnsShape        = "record"

	socketColor        = "#ff6600"
	socketRuntimeColor = "#ffe0cc"
	socketShape        = "record"
)

// NodeGenerationType is used to indicate if a node was generated by a runtime or snapshot event
type NodeGenerationType string

var (
	// Runtime is a node that was added at runtime
	Runtime NodeGenerationType = "runtime"
	// Snapshot is a node that was added during the snapshot
	Snapshot NodeGenerationType = "snapshot"
)

type node struct {
	ID        string
	Label     string
	Size      int
	Color     string
	FillColor string
	Shape     string
}

type edge struct {
	Link  string
	Color string
}

type graph struct {
	Title string
	Nodes map[string]node
	Edges []edge
}

// GraphTemplate is the template used to generate graphs
var GraphTemplate = `digraph {
		label = "{{ .Title }}"
		labelloc =  "t"
		fontsize = 75
		fontcolor = "black"
		fontname = "arial"
		ratio = expand
		ranksep = 2

		graph [pad=2]
		node [margin=0.3, padding=1, penwidth=3]
		edge [penwidth=2]

		{{ range .Nodes }}
		{{ .ID }} [label="{{ .Label }}", fontsize={{ .Size }}, shape={{ .Shape }}, fontname = "arial", color="{{ .Color }}", fillcolor="{{ .FillColor }}", style="filled"]{{ end }}

		{{ range .Edges }}
		{{ .Link }} [arrowhead=none, color="{{ .Color }}"]
		{{ end }}
}`

// EncodeDOT encodes an activity dump in the DOT format
func (ad *ActivityDump) EncodeDOT() (*bytes.Buffer, error) {
	ad.Lock()
	defer ad.Unlock()

	title := fmt.Sprintf("%s: %s", ad.DumpMetadata.Name, ad.GetSelectorStr())
	data := ad.prepareGraphData(title)
	t := template.Must(template.New("tmpl").Parse(GraphTemplate))
	raw := bytes.NewBuffer(nil)
	if err := t.Execute(raw, data); err != nil {
		return nil, fmt.Errorf("couldn't encode %s in %s: %w", ad.GetSelectorStr(), dump.DOT, err)
	}
	return raw, nil
}

func (ad *ActivityDump) prepareGraphData(title string) graph {
	data := graph{
		Title: title,
		Nodes: make(map[string]node),
	}

	for _, p := range ad.ProcessActivityTree {
		ad.prepareProcessActivityNode(p, &data)
	}

	return data
}

func (ad *ActivityDump) prepareProcessActivityNode(p *ProcessActivityNode, data *graph) {
	var args string
	if argv, _ := ad.adm.probeContext.Resolvers.ProcessResolver.GetProcessScrubbedArgv(&p.Process); len(argv) > 0 {
		args = strings.ReplaceAll(strings.Join(argv, " "), "\"", "\\\"")
		args = strings.ReplaceAll(args, "\n", " ")
		args = strings.ReplaceAll(args, ">", "\\>")
		args = strings.ReplaceAll(args, "|", "\\|")
	}
	pan := node{
		ID:    p.GetID(),
		Label: fmt.Sprintf("%s %s", p.Process.FileEvent.PathnameStr, args),
		Size:  60,
		Color: processColor,
		Shape: processShape,
	}
	switch p.GenerationType {
	case Runtime:
		pan.FillColor = processRuntimeColor
	case Snapshot:
		pan.FillColor = processSnapshotColor
	}
	data.Nodes[p.GetID()] = pan

	for _, n := range p.Sockets {
		data.Edges = append(data.Edges, edge{
			Link:  p.GetID() + " -> " + p.GetID() + n.GetID(),
			Color: socketColor,
		})
		ad.prepareSocketNode(n, data, p.GetID())
	}
	for _, n := range p.DNSNames {
		data.Edges = append(data.Edges, edge{
			Link:  p.GetID() + " -> " + p.GetID() + n.GetID(),
			Color: dnsColor,
		})
		ad.prepareDNSNode(n, data, p.GetID())
	}
	for _, f := range p.Files {
		data.Edges = append(data.Edges, edge{
			Link:  p.GetID() + " -> " + p.GetID() + f.GetID(),
			Color: fileColor,
		})
		ad.prepareFileNode(f, data, "", p.GetID())
	}
	for _, child := range p.Children {
		data.Edges = append(data.Edges, edge{
			Link:  p.GetID() + " -> " + child.GetID(),
			Color: processColor,
		})
		ad.prepareProcessActivityNode(child, data)
	}
}

func (ad *ActivityDump) prepareDNSNode(n *DNSNode, data *graph, processID string) {
	if len(n.requests) == 0 {
		// save guard, this should never happen
		return
	}
	name := n.requests[0].Name + " (" + (model.QType(n.requests[0].Type).String())
	for _, req := range n.requests[1:] {
		name += ", " + model.QType(req.Type).String()
	}
	name += ")"

	dnsNode := node{
		ID:        processID + n.GetID(),
		Label:     name,
		Size:      30,
		Color:     dnsColor,
		FillColor: dnsRuntimeColor,
		Shape:     dnsShape,
	}
	data.Nodes[dnsNode.ID] = dnsNode
}

func (ad *ActivityDump) prepareSocketNode(n *SocketNode, data *graph, processID string) {
	var name string
	if n.Bind.IP != "<nil>" {
		name = fmt.Sprintf("%s/%s/%d", n.Family, n.Bind.IP, n.Bind.Port)
	} else { // show other addr families, even if they are not parsed yet
		name = fmt.Sprintf("%s", n.Family)
	}

	socketNode := node{
		ID:        processID + n.GetID(),
		Label:     name,
		Size:      30,
		Color:     socketColor,
		FillColor: socketRuntimeColor,
		Shape:     socketShape,
	}
	data.Nodes[socketNode.ID] = socketNode
}

func (ad *ActivityDump) prepareFileNode(f *FileActivityNode, data *graph, prefix string, processID string) {
	mergedID := processID + f.GetID()
	fn := node{
		ID:    mergedID,
		Label: f.getNodeLabel(),
		Size:  30,
		Color: fileColor,
		Shape: fileShape,
	}
	switch f.GenerationType {
	case Runtime:
		fn.FillColor = fileRuntimeColor
	case Snapshot:
		fn.FillColor = fileSnapshotColor
	}
	data.Nodes[mergedID] = fn

	for _, child := range f.Children {
		data.Edges = append(data.Edges, edge{
			Link:  mergedID + " -> " + processID + child.GetID(),
			Color: fileColor,
		})
		ad.prepareFileNode(child, data, prefix+f.Name, processID)
	}
}
