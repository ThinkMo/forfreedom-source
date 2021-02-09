+++
keywords = ["k8s", 'kubelet']
title = "kubelet源码解析之PLEG"
categories = ["k8s"]
disqusIdentifier = "k8s_kubelet_source"
comments = true
clearReading = true
date = 2021-02-09T16:01:30+08:00 
showSocial = false
showPagination = true
showTags = true
showDate = true
+++


## kubelet源码分析之PLEG

### PLEG介绍

Pleg(Pod Lifecycle Event Generator) 是kubelet 的核心模块，PLEG周期性调用container runtime获取本节点containers/sandboxes的信息(像docker ps)，并与自身维护的podRecords信息进行对比，生成对应的 PodLifecycleEvent并发送到plegCh中，在kubelet syncLoop中对plegCh进行消费处理，最终达到用户的期望状态

![pleg](/images/pleg.png)

在之前的kubelet版本中由每个pod的podWorker的goroutine来查询runtime进行对比，当pod数量逐渐增大时，大量周期性的查询导致高cpu使用率、低性能、难以扩展等问题，为了改进以上问题，引入了PLEG


### 创建
在/pkg/kubelet/kubelet.go:660 在函数KubeletNewMainKubelet中伴随Kubelet结构体创建

```
    // 传入runtime、chan缓冲大小、定时周期、podCache创建pleg
    klet.pleg = pleg.NewGenericPLEG(klet.containerRuntime, plegChannelCapacity, plegRelistPeriod, klet.podCache, clock.RealClock{})
```

pkg/kubelet/pleg/generic.go:109 工厂函数NewGenericPLEG创建返回接口类型PodLifecycleEventGenerator

```
// NewGenericPLEG instantiates a new GenericPLEG object and return it.
func NewGenericPLEG(runtime kubecontainer.Runtime, channelCapacity int,
        relistPeriod time.Duration, cache kubecontainer.Cache, clock clock.Clock) PodLifecycleEventGenerator {
        return &GenericPLEG{
                // 定时relist周期
                relistPeriod: relistPeriod,
                // KubeGenericRuntimeManager
                runtime:      runtime,
                // 与kubelet通信带缓冲chan
                eventChannel: make(chan *PodLifecycleEvent, channelCapacity),
                podRecords:   make(podRecords),
                // podCache
                cache:        cache,
                clock:        clock,
        }
}

// podRecords定义
type podRecord struct {
        // 历史pod
        old     *kubecontainer.Pod
        // 当前pod
        current *kubecontainer.Pod
}

type podRecords map[types.UID]*podRecor
```

### 启动
在/pkg/kubelet/kubelet.go:1364 Run中启动

```
    kl.pleg.Start()
```

### 具体逻辑
- 消费端

在Kubelet的循环syncLoop中 plegCh := kl.pleg.Watch()获得pleg的chan由Kubelet进行消费处理

- 生产端

pkg/kubelet/pleg/generic.go:130 定期执行g.relist，默认1s

```
func (g *GenericPLEG) Start() {
        // 每隔g.relistPeriod默认1s执行g.relist
        go wait.Until(g.relist, g.relistPeriod, wait.NeverStop)
}
```
pkg/kubelet/pleg/generic.go:190 relist

1. 请求runtime获得pod，根据sandbox/container构建pod
2. 更新metrics、podRecords的current
3. 对比podRecords中的old、current生成event
4. 更新cache，发送event

```
// relist queries the container runtime for list of pods/containers, compare
// with the internal pods/containers, and generates events accordingly.
func (g *GenericPLEG) relist() {
        klog.V(5).Infof("GenericPLEG: Relisting")

        if lastRelistTime := g.getRelistTime(); !lastRelistTime.IsZero() {
                metrics.PLEGRelistInterval.Observe(metrics.SinceInSeconds(lastRelistTime))
        }

        timestamp := g.clock.Now()
        defer func() {
                metrics.PLEGRelistDuration.Observe(metrics.SinceInSeconds(timestamp))
        }()

        // 获得所有pods，根据runtime获得sandbox/containers并以此构建pod
        podList, err := g.runtime.GetPods(true)
        if err != nil {
                klog.Errorf("GenericPLEG: Unable to retrieve pods: %v", err)
                return
        }

        g.updateRelistTime(timestamp)

        pods := kubecontainer.Pods(podList)
        // 更新运行的container、sandbox数量
        updateRunningPodAndContainerMetrics(pods)
        // 更新podRecords中current
        g.podRecords.setCurrent(pods)

        // 对比并生成event
        eventsByPodID := map[types.UID][]*PodLifecycleEvent{}
        for pid := range g.podRecords {
                oldPod := g.podRecords.getOld(pid)
                pod := g.podRecords.getCurrent(pid)
                // 获取oldPod、pod中所有container、sandbox
                allContainers := getContainersFromPods(oldPod, pod)
                for _, container := range allContainers {
                        // 获取container在oldPod、pod中的state对比生成event
                        events := computeEvents(oldPod, pod, &container.ID)
                        for _, e := range events {
                                // 添加到eventsByPodID
                                updateEvents(eventsByPodID, e)
                        }
                }
        }

        var needsReinspection map[types.UID]*kubecontainer.Pod
        if g.cacheEnabled() {
                needsReinspection = make(map[types.UID]*kubecontainer.Pod)
        }

        // If there are events associated with a pod, we should update the
        // podCache.
        for pid, events := range eventsByPodID {
                pod := g.podRecords.getCurrent(pid)
                if g.cacheEnabled() {
                        // 更新cache，如果失败下次重试
                        if err := g.updateCache(pod, pid); err != nil {
                                klog.V(4).Infof("PLEG: Ignoring events for pod %s/%s: %v", pod.Name, pod.Namespace, err)
                                needsReinspection[pid] = pod
                                continue
                        } else {
                                delete(g.podsToReinspect, pid)
                        }
                }
                // 更新podRecords，old更新为current
                g.podRecords.update(pid)
                for i := range events {
                        // Filter out events that are not reliable and no other components use yet.
                        if events[i].Type == ContainerChanged {
                                continue
                        }
                        select {
                        // 发送event
                        case g.eventChannel <- events[i]:
                        default:
                                metrics.PLEGDiscardEvents.Inc()
                                klog.Error("event channel is full, discard this relist() cycle event")
                        }
                }
        }

        if g.cacheEnabled() {
                // 重试更新cache
                if len(g.podsToReinspect) > 0 {
                        klog.V(5).Infof("GenericPLEG: Reinspecting pods that previously failed inspection")
                        for pid, pod := range g.podsToReinspect {
                                if err := g.updateCache(pod, pid); err != nil {
                                        // Rely on updateCache calling GetPodStatus to log the actual error.
                                        klog.V(5).Infof("PLEG: pod %s/%s failed reinspection: %v", pod.Name, pod.Namespace, err)
                                        needsReinspection[pid] = pod
                                }
                        }
                }

                // Update the cache timestamp.  This needs to happen *after*
                // all pods have been properly updated in the cache.
                g.cache.UpdateTime(timestamp)
        }

        // 更新待重试
        g.podsToReinspect = needsReinspection
}
```

pkg/kubelet/pleg/generic.go:333 computeEvents对比生成event，参数为oldPod、current pod及pod内的container

```
func computeEvents(oldPod, newPod *kubecontainer.Pod, cid *kubecontainer.ContainerID) []*PodLifecycleEvent {
        var pid types.UID
        if oldPod != nil {
                pid = oldPod.ID
        } else if newPod != nil {
                pid = newPod.ID
        }
        // 根据cid获得container将state转为plegState
        oldState := getContainerState(oldPod, cid)
        newState := getContainerState(newPod, cid)
        // 对比生成event
        return generateEvents(pid, cid.ID, oldState, newState)
}
```

pkg/kubelet/pleg/generic.go:150   generateEvents 对比生成event

```
func generateEvents(podID types.UID, cid string, oldState, newState plegContainerState) []*PodLifecycleEvent {
        // 相同返回nil
        if newState == oldState {
                return nil
        }
        // 不相同时，根据newState判断
        klog.V(4).Infof("GenericPLEG: %v/%v: %v -> %v", podID, cid, oldState, newState)
        switch newState {
        case plegContainerRunning:
                return []*PodLifecycleEvent{{ID: podID, Type: ContainerStarted, Data: cid}}
        case plegContainerExited:
                return []*PodLifecycleEvent{{ID: podID, Type: ContainerDied, Data: cid}}
        case plegContainerUnknown:
                return []*PodLifecycleEvent{{ID: podID, Type: ContainerChanged, Data: cid}}
        case plegContainerNonExistent:
                switch oldState {
                case plegContainerExited:
                        // We already reported that the container died before.
                        return []*PodLifecycleEvent{{ID: podID, Type: ContainerRemoved, Data: cid}}
                default:
                        return []*PodLifecycleEvent{{ID: podID, Type: ContainerDied, Data: cid}, {ID: podID, Type: ContainerRemoved, Data: cid}}
                }
        default:
                panic(fmt.Sprintf("unrecognized container state: %v", newState))
        }
}
```

### 参考
[pelg设计文档](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/node/pod-lifecycle-event-generator.md)
