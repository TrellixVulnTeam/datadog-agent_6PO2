// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubelet
// +build kubelet

package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSource(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{container},
		},
		Spec: kubelet.Spec{
			Containers: []kubelet.ContainerSpec{{
				Name:  "foo",
				Image: "bar",
			}},
		},
	}

	source, err := scheduler.getSource(pod, container)
	assert.Nil(t, err)
	assert.Equal(t, config.FileType, source.Config.Type)
	assert.Equal(t, "buu/fuz/foo", source.Name)
	assert.Equal(t, "/var/log/pods/buu_fuz_baz/foo/*.log", filepath.ToSlash(source.Config.Path))
	assert.Equal(t, "boo", source.Config.Identifier)
	assert.Equal(t, "bar", source.Config.Source)
	assert.Equal(t, "bar", source.Config.Service)
}

func TestGetSourceShouldBeOverridenByAutoDiscoveryAnnotation(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
			Annotations: map[string]string{
				"ad.datadoghq.com/foo.logs": `[{"source":"any_source","service":"any_service","tags":["tag1","tag2"]}]`,
			},
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{container},
		},
	}

	source, err := scheduler.getSource(pod, container)
	assert.Nil(t, err)
	assert.Equal(t, config.FileType, source.Config.Type)
	assert.Equal(t, "buu/fuz/foo", source.Name)
	assert.Equal(t, "/var/log/pods/buu_fuz_baz/foo/*.log", filepath.ToSlash(source.Config.Path))
	assert.Equal(t, "boo", source.Config.Identifier)
	assert.Equal(t, "any_source", source.Config.Source)
	assert.Equal(t, "any_service", source.Config.Service)
	assert.True(t, contains(source.Config.Tags, "tag1", "tag2"))
}

func TestGetSourceShouldFailWithInvalidAutoDiscoveryAnnotation(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
			Annotations: map[string]string{
				// missing [ ]
				"ad.datadoghq.com/foo.logs": `{"source":"any_source","service":"any_service","tags":["tag1","tag2"]}`,
			},
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{container},
		},
	}

	source, err := scheduler.getSource(pod, container)
	assert.NotNil(t, err)
	assert.Nil(t, source)
}

func TestGetSourceAddContainerdParser(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{container},
		},
	}

	source, err := scheduler.getSource(pod, container)
	assert.Nil(t, err)
	assert.Equal(t, config.FileType, source.Config.Type)
}

func TestContainerCollectAll(t *testing.T) {
	schedulerCollectAll := getScheduler(true)
	schedulerCollectAllDisabled := getScheduler(false)
	containerFoo := kubelet.ContainerStatus{
		Name:  "fooName",
		Image: "fooImage",
		ID:    "docker://fooID",
	}
	containerBar := kubelet.ContainerStatus{
		Name:  "barName",
		Image: "barImage",
		ID:    "docker://barID",
	}
	containerBaz := kubelet.ContainerStatus{
		Name:  "bazName",
		Image: "bazImage",
		ID:    "containerd://bazID",
	}
	podFoo := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "podName",
			Namespace: "podNamespace",
			UID:       "podUIDFoo",
			Annotations: map[string]string{
				"ad.datadoghq.com/fooName.logs": `[{"source":"any_source","service":"any_service"}]`,
			},
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{containerFoo, containerBar},
		},
	}
	podBar := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "podName",
			Namespace: "podNamespace",
			UID:       "podUIDBarr",
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{containerFoo, containerBar},
		},
	}
	podBaz := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "podName",
			Namespace: "podNamespace",
			UID:       "podUIDBaz",
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{containerBaz},
		},
	}

	source, err := schedulerCollectAll.getSource(podFoo, containerFoo)
	assert.Nil(t, err)
	assert.Equal(t, "fooID", source.Config.Identifier)
	source, err = schedulerCollectAll.getSource(podBar, containerBar)
	assert.Nil(t, err)
	assert.Equal(t, "barID", source.Config.Identifier)

	source, err = schedulerCollectAllDisabled.getSource(podFoo, containerFoo)
	assert.Nil(t, err)
	assert.Equal(t, "fooID", source.Config.Identifier)
	source, err = schedulerCollectAllDisabled.getSource(podBar, containerBar)
	assert.Equal(t, errCollectAllDisabled, err)
	assert.Nil(t, source)

	source, err = schedulerCollectAll.getSource(podBaz, containerBaz)
	assert.Nil(t, err)
	assert.Equal(t, "bazID", source.Config.Identifier)
}

func TestGetPath(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
		},
		Status: kubelet.Status{
			Containers: []kubelet.ContainerStatus{container},
		},
	}

	basePath, err := ioutil.TempDir("", "")
	defer os.RemoveAll(basePath)
	assert.Nil(t, err)

	// v1.14+ (default)
	podDirectory := "buu_fuz_baz"
	path := scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo", "*.log"), path)

	// v1.10 - v1.13
	podDirectory = "baz"
	containerDirectory := "foo"

	err = os.MkdirAll(filepath.Join(basePath, podDirectory, containerDirectory), 0777)
	assert.Nil(t, err)

	path = scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo", "*.log"), path)

	// v1.9
	os.RemoveAll(basePath)
	podDirectory = "baz"
	logFile := "foo_1.log"

	err = os.MkdirAll(filepath.Join(basePath, podDirectory), 0777)
	assert.Nil(t, err)

	_, err = os.Create(filepath.Join(basePath, podDirectory, logFile))
	assert.Nil(t, err)

	path = scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo_*.log"), path)
}

func TestGetSourceServiceNameOrder(t *testing.T) {
	tests := []struct {
		name            string
		sFunc           func(string, string) string
		pod             *kubelet.Pod
		container       kubelet.ContainerStatus
		wantServiceName string
		wantSourceName  string
		wantErr         bool
	}{
		{
			name:  "log config",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
					Annotations: map[string]string{
						"ad.datadoghq.com/fooName.logs": `[{"source":"foo","service":"annotServiceName"}]`,
					},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "annotServiceName",
			wantSourceName:  "foo",
			wantErr:         false,
		},
		{
			name:  "standard tags",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
					Annotations: map[string]string{
						"ad.datadoghq.com/fooName.logs": `[{"source":"foo"}]`,
					},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "stdServiceName",
			wantSourceName:  "foo",
			wantErr:         false,
		},
		{
			name:  "standard tags, undefined source, use image as source",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
				},
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "stdServiceName",
			wantSourceName:  "fooImage",
			wantErr:         false,
		},
		{
			name:  "image name",
			sFunc: func(n, e string) string { return "" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
				},
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "fooImage",
			wantSourceName:  "fooImage",
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Scheduler{
				collectAll:      true,
				kubeutil:        kubelet.NewKubeUtil(),
				serviceNameFunc: tt.sFunc,
			}
			got, err := l.getSource(tt.pod, tt.container)
			if (err != nil) != tt.wantErr {
				t.Errorf("Launcher.getSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.wantServiceName, got.Config.Service)
			assert.Equal(t, tt.wantSourceName, got.Config.Source)
		})
	}
}

func TestGetShortImageName(t *testing.T) {
	tests := []struct {
		name          string
		pod           *kubelet.Pod
		containerName string
		wantImageName string
		wantErr       bool
	}{
		{
			name: "standard",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "fooImage",
			wantErr:       false,
		},
		{
			name: "empty",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "",
			wantErr:       true,
		},
		{
			name: "with prefix",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "org/fooImage:tag",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "fooImage",
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := getScheduler(true)

			got, err := l.getShortImageName(tt.pod, tt.containerName)
			if got != tt.wantImageName {
				t.Errorf("Launcher.getShortImageName() = %s, want %s", got, tt.wantImageName)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Launcher.getShortImageName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRetryGettingKubeUtilStops(t *testing.T) {
	s := &Scheduler{stop: make(chan struct{})}

	retryForever := func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		return nil, fastRetrier()
	}

	got := make(chan kubelet.KubeUtilInterface)
	go func() {
		got <- s.getKubeUtil(retryForever)
	}()

	close(s.stop)
	require.Nil(t, <-got)
}

func TestRetryGettingKubeUtilSuccess(t *testing.T) {
	s := &Scheduler{stop: make(chan struct{})}

	var tries int
	retryAFewTimes := func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		tries++
		if tries > 3 {
			return dummyKubeUtil{}, nil
		}
		return nil, fastRetrier()
	}

	require.NotNil(t, s.getKubeUtil(retryAFewTimes))
}

func TestRetry(t *testing.T) {
	containerName := "fooName"
	containerType := "docker"
	containerID := "123456789abcdefoo"
	imageName := "fooImage"
	serviceName := "fooService"

	mgr := &schedulers.MockSourceManager{}
	l := &Scheduler{
		collectAll:         true,
		kubeutil:           dummyKubeUtil{shouldRetry: true},
		pendingRetries:     make(map[string]*retryOps),
		retryOperations:    make(chan *retryOps),
		serviceNameFunc:    func(n, e string) string { return serviceName },
		mgr:                mgr,
		sourcesByContainer: make(map[string]*config.LogSource),
	}

	service := service.NewService(containerType, containerID)
	l.addSource(service)

	ops := <-l.retryOperations

	assert.Equal(t, containerType, ops.service.Type)
	assert.Equal(t, containerID, ops.service.Identifier)

	l.kubeutil = dummyKubeUtil{
		name:        containerName,
		id:          containerID,
		image:       imageName,
		shouldRetry: false,
	}

	mu := sync.Mutex{}
	mu.Lock()
	defer mu.Unlock()
	go func() {
		l.addSource(ops.service)
		mu.Unlock()
	}()
	// Ensure l.addSource is completely done
	mu.Lock()

	require.Equal(t, 1, len(mgr.Events))
	source := mgr.Events[0].Source

	assert.Equal(t, 1, len(l.sourcesByContainer))

	assert.Equal(t, containerID, source.Config.Identifier)
	assert.Equal(t, serviceName, source.Config.Service)
	assert.Equal(t, imageName, source.Config.Source)

	assert.Equal(t, 0, len(l.pendingRetries))
	assert.Equal(t, 1, len(l.sourcesByContainer))
}

type dummyKubeUtil struct {
	kubelet.KubeUtilInterface
	name        string
	image       string
	id          string
	shouldRetry bool
}

func (d dummyKubeUtil) GetStatusForContainerID(pod *kubelet.Pod, containerID string) (kubelet.ContainerStatus, error) {
	status := kubelet.ContainerStatus{
		Name:  d.name,
		Image: d.image,
		ID:    d.id,
		Ready: true,
		State: kubelet.ContainerState{},
	}
	return status, nil
}

func (d dummyKubeUtil) GetSpecForContainerName(pod *kubelet.Pod, containerName string) (kubelet.ContainerSpec, error) {
	spec := kubelet.ContainerSpec{
		Name:  d.name,
		Image: d.image,
	}
	return spec, nil
}

func (d dummyKubeUtil) GetPodForEntityID(ctx context.Context, entityID string) (*kubelet.Pod, error) {
	if d.shouldRetry {
		return nil, errors.NewRetriable("dummy error", fmt.Errorf("retriable error"))
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{},
		Spec: kubelet.Spec{
			Containers: []kubelet.ContainerSpec{{
				Name:  d.name,
				Image: d.image,
			}},
		},
	}
	return pod, nil
}

func getScheduler(collectAll bool) *Scheduler {
	k := kubelet.NewKubeUtil()
	return &Scheduler{
		collectAll:      collectAll,
		kubeutil:        k,
		serviceNameFunc: func(string, string) string { return "" },
	}
}

// contains returns true if the list contains all the items.
func contains(list []string, items ...string) bool {
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	for _, elt := range list {
		if _, exists := m[elt]; !exists {
			return false
		}
	}
	return true
}

func fastRetrier() *retry.Retrier {
	retr := &retry.Retrier{}
	retr.SetupRetrier(&retry.Config{
		Strategy:          retry.Backoff,
		InitialRetryDelay: 1 * time.Millisecond,
		MaxRetryDelay:     1 * time.Millisecond,
	})
	return retr
}
