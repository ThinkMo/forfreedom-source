+++
keywords = ["k8s", 'kubelet']
title = "kubelet源码解析(上)"
categories = ["k8s"]
disqusIdentifier = "k8s_kubelet_source"
comments = true
clearReading = true
date = 2020-12-31T17:13:30+08:00 
showSocial = false
showPagination = true
showTags = true
showDate = true
+++


### kubelet介绍

在k8s集群中的每个节点上都运行着一个kubelet服务进程，其主要负责向apiserver注册节点、管理pod及pod中的容器，并通过 cAdvisor 监控节点和容器的资源。

- 节点管理：节点注册、节点状态更新(定期心跳)
- pod管理：接受来自apiserver、file、http等PodSpec，并确保这些 PodSpec 中描述的容器处于运行状态且运行状况良好
- 容器健康检查：通过ReadinessProbe、LivenessProbe两种探针检查容器健康状态
- 资源监控：通过 cAdvisor 获取其所在节点及容器的监控数据


### 深入kubelet工作原理

![kubelet](/images/kubelet.png)

从上图可以看出kubelet的主要工作逻辑在SyncLoop控制循环中，处理pod更新事件、pod生命周期变化、周期sync事件、定时清理事件；SyncLoop旁还有处理其他逻辑的控制循环，例如处理pod状态同步的statusManager，处理健康检查的probeManager等。

下面将从kubelet源码来分析各个环节的处理逻辑。

kubelet代码(版本1.19)主要位于cmd/kubelet与pkg/kubelet下，首先看下kubelet启动流程与初始化

```
// kubelet依赖cobra命令行库，创建kubelet command并执行
cmd/kubelet/kubelet.go:34          func main()
// 处理flags、configfile验证、初始化kubletServer/kubeletDeps(依赖注入)、信号处理ctx，调用run
cmd/kubelet/app/server.go:113      func NewKubeletCommand() *cobra.Command
// client(kube\event\heartbeat)、auth、cgroup、cadvisor、containerManager、runtime初始化(dockershim...)、healthz监听，调用RunKubelet
cmd/kubelet/app/server.go:472      func run
// 创建Kubelet关键结构体，执行Kubelet Run进入主循环，运行kubelet server、只读端口等
cmd/kubelet/app/server.go:1071     func RunKubelet

// 先看下NewMainKubelet创建初始化Kubelet关键结构体函数
cmd/kubelet/kubelet.go:333
func NewMainKubelet(...){
    // 创建PodConfig，watch apiserver、file、http等
	if kubeDeps.PodConfig == nil {
		var err error
		kubeDeps.PodConfig, err = makePodSourceConfig(kubeCfg, kubeDeps, nodeName)
		if err != nil {
			return nil, err
		}
	}
	// 创建service informer、node、oom watcher
	// 创建Kubelet
	// 创建各种manager例如secret、configMap
	// 创建podManager，管理pod信息
	klet.podManager = kubepod.NewBasicPodManager(mirrorPodClient, secretManager, configMapManager)
	// 创建pleg
	klet.pleg = pleg.NewGenericPLEG(klet.containerRuntime, plegChannelCapacity, plegRelistPeriod, klet.podCache, clock.RealClock{})
	// 创建podWorker，syncPod为每个pod处理逻辑函数，在每个pod的goroutine中对pod更新进行同步
	klet.podWorkers = newPodWorkers(klet.syncPod, kubeDeps.Recorder, klet.workQueue,   klet.resyncInterval, backOffPeriod, klet.podCache
}

// Kubelet Run方法
pkg/kubelet/kubelet.go:1314
func (kl *Kubelet) Run(updates <-chan kubetypes.PodUpdate) {
    // 初始化与runtime无关的逻辑，metrics、imageManager等
	if err := kl.initializeModules(); err != nil {
		kl.recorder.Eventf(kl.nodeRef, v1.EventTypeWarning, events.KubeletSetupFailed, err.Error())
		klog.Fatal(err)
	}
	// 启动volume manager
	go kl.volumeManager.Run(kl.sourcesReady, wait.NeverStop)

	if kl.kubeClient != nil {
		// 同步node状态
		go wait.Until(kl.syncNodeStatus, kl.nodeStatusUpdateFrequency, wait.NeverStop)
		go kl.fastStatusUpdateOnce()
		// 启动node lease
		go kl.nodeLeaseController.Run(wait.NeverStop)
	}
	// runtime首次初始化、定时更新
	go wait.Until(kl.updateRuntimeUp, 5*time.Second, wait.NeverStop)

	// 设置iptables规则
	if kl.makeIPTablesUtilChains {
		kl.initNetworkUtil()
	}

	// 启动podKiller，监听podKiller.podKillingCh
	go wait.Until(kl.podKiller.PerformPodKillingWork, 1*time.Second, wait.NeverStop)

	// 启动statusManager、probeManager
	kl.statusManager.Start()
	kl.probeManager.Start()

	// Start syncing RuntimeClasses if enabled.
	if kl.runtimeClassManager != nil {
		kl.runtimeClassManager.Start(wait.NeverStop)
	}

	// 启动pleg
	kl.pleg.Start()
	// 进入主循环
	kl.syncLoop(updates, kl)
}
```
上述代码逻辑实现kubelet参数、配置、信号处理注册，初始化依赖、Kubelet启动Manager, 进入各自manager处理逻辑，最后进入kubelet主循环逻辑，主循环有5个事件源

- configCh                    podConfig处理来自apiserver、file、http的pod更新，在创建Kubelet时初始化
- handler                      liveness manager处理，在创建Kubelet时初始化，为statusManager的一部分
- syncCh                      time定时同步pod
- housekeepingCh         time定时清理pod
- plegCh                      处理来自pleg的消息，在创建Kubelet时初始化，关于pleg可以看[这里](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/node/pod-lifecycle-event-generator.md)，简单说对容器状态感知由每个pod worker(goroutine)轮询改为pleg

```
// kubelet事件循环函数
pkg/kubelet/kubelet.go:1814
func (kl *Kubelet) syncLoopIteration(configCh <-chan kubetypes.PodUpdate, handler SyncHandler,
	syncCh <-chan time.Time, housekeepingCh <-chan time.Time, plegCh <-chan *pleg.PodLifecycleEvent) bool {
	select {
	// 处理来自apiserver、file、http的pod增删改查，最终走到Kubelet的syncPod处理
	case u, open := <-configCh:
		if !open {
			klog.Errorf("Update channel is closed. Exiting the sync loop.")
			return false
		}
		switch u.Op {
		case kubetypes.ADD:
			klog.V(2).Infof("SyncLoop (ADD, %q): %q", u.Source, format.Pods(u.Pods))
			handler.HandlePodAdditions(u.Pods)
		case kubetypes.UPDATE:
			klog.V(2).Infof("SyncLoop (UPDATE, %q): %q", u.Source, format.PodsWithDeletionTimestamps(u.Pods))
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.REMOVE:
			klog.V(2).Infof("SyncLoop (REMOVE, %q): %q", u.Source, format.Pods(u.Pods))
			handler.HandlePodRemoves(u.Pods)
		case kubetypes.RECONCILE:
			klog.V(4).Infof("SyncLoop (RECONCILE, %q): %q", u.Source, format.Pods(u.Pods))
			handler.HandlePodReconcile(u.Pods)
		case kubetypes.DELETE:
			klog.V(2).Infof("SyncLoop (DELETE, %q): %q", u.Source, format.Pods(u.Pods))
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.SET:
			klog.Errorf("Kubelet does not support snapshot update")
		default:
			klog.Errorf("Invalid event type received: %d.", u.Op)
		}
		kl.sourcesReady.AddSource(u.Source)
    // 处理来自runtime的容器变化
	case e := <-plegCh:
		if e.Type == pleg.ContainerStarted {
			kl.lastContainerStartedTime.Add(e.ID, time.Now())
		}
		if isSyncPodWorthy(e) {
			if pod, ok := kl.podManager.GetPodByUID(e.ID); ok {
				klog.V(2).Infof("SyncLoop (PLEG): %q, event: %#v", format.Pod(pod), e)
				handler.HandlePodSyncs([]*v1.Pod{pod})
			} else {
				klog.V(4).Infof("SyncLoop (PLEG): ignore irrelevant event: %#v", e)
			}
		}
		if e.Type == pleg.ContainerDied {
			if containerID, ok := e.Data.(string); ok {
				kl.cleanUpContainersInPod(e.ID, containerID)
			}
		}
	// 同步pod状态，最终走到Kubelet的syncPod处理
	case <-syncCh:
		podsToSync := kl.getPodsToSync()
		if len(podsToSync) == 0 {
			break
		}
		klog.V(4).Infof("SyncLoop (SYNC): %d pods; %s", len(podsToSync), format.Pods(podsToSync))
		handler.HandlePodSyncs(podsToSync)
	// 处理probe fail，最终走到Kubelet的syncPod处理
	case update := <-kl.livenessManager.Updates():
		if update.Result == proberesults.Failure {
			pod, ok := kl.podManager.GetPodByUID(update.PodUID)
			if !ok {
				klog.V(4).Infof("SyncLoop (container unhealthy): ignore irrelevant update: %#v", update)
				break
			}
			klog.V(1).Infof("SyncLoop (container unhealthy): %q", format.Pod(pod))
			handler.HandlePodSyncs([]*v1.Pod{pod})
		}
	case <-housekeepingCh:
		if !kl.sourcesReady.AllReady() {
			klog.V(4).Infof("SyncLoop (housekeeping, skipped): sources aren't ready yet.")
		} else {
			klog.V(4).Infof("SyncLoop (housekeeping)")
			if err := handler.HandlePodCleanups(); err != nil {
				klog.Errorf("Failed cleaning pods: %v", err)
			}
		}
	}
	return true
}
```

对不同事件有不同的处理handler，大部分handler都会通过dispatchWork进入podWorkers.UpdatePod

```
// podWorkers存储每个pod的goroutine并处理pod的update到对应goroutine
pkg/kubelet/pod_workers.go:200
func (p *podWorkers) UpdatePod(options *UpdatePodOptions) {
	pod := options.Pod
	uid := pod.UID
	var podUpdates chan UpdatePodOptions
	var exists bool

	p.podLock.Lock()
	defer p.podLock.Unlock()
	// pod是否已存在，如果不存在则创建channel，启动对应pod的goroutine
	if podUpdates, exists = p.podUpdates[uid]; !exists {
		podUpdates = make(chan UpdatePodOptions, 1)
		p.podUpdates[uid] = podUpdates
		go func() {
			defer runtime.HandleCrash()
			// pod处理函数
			p.managePodLoop(podUpdates)
		}()
	}
	// pod存在且空闲则写入，否则暂存最近的更新
	if !p.isWorking[pod.UID] {
		p.isWorking[pod.UID] = true
		podUpdates <- *options
	} else {
		// SyncPodKill不会被覆盖
		if !found || update.UpdateType != kubetypes.SyncPodKill {
			p.lastUndeliveredWorkUpdate[pod.UID] = *options
		}
	}
}
// pod的处理goroutine，监听事件并调用Kubelet的方法syncPod处理
pkg/kubelet/pod_workers.go:158
func (p *podWorkers) managePodLoop(podUpdates <-chan UpdatePodOptions) {
	var lastSyncTime time.Time
	for update := range podUpdates {
		err := func() error {
			podUID := update.Pod.UID
			status, err := p.podCache.GetNewerThan(podUID, lastSyncTime)
			if err != nil {
				p.recorder.Eventf(update.Pod, v1.EventTypeWarning, events.FailedSync, "error determining status: %v", err)
				return err
			}
			// 调用Kubelet的方法syncPod
			err = p.syncPodFn(syncPodOptions{
				mirrorPod:      update.MirrorPod,
				pod:            update.Pod,
				podStatus:      status,
				killPodOptions: update.KillPodOptions,
				updateType:     update.UpdateType,
			})
			lastSyncTime = time.Now()
			return err
		}()
		if update.OnCompleteFunc != nil {
			update.OnCompleteFunc(err)
		}
		if err != nil {
			klog.Errorf("Error syncing pod %s (%q), skipping: %v", update.Pod.UID, format.Pod(update.Pod), err)
		}
		// 查看lastUndeliveredWorkUpdate是否有未处理的事件，继续处理
		p.wrapUp(update.Pod.UID, err)
	}
}
```

syncPod: 在交由runtime完成真正的处理逻辑之前，进行一些预处理

```
func (kl *Kubelet) syncPod(o syncPodOptions) error {
	pod := o.pod
	mirrorPod := o.mirrorPod
	podStatus := o.podStatus
	updateType := o.updateType

	// 处理kill Pod
	if updateType == kubetypes.SyncPodKill {
		killPodOptions := o.killPodOptions
		if killPodOptions == nil || killPodOptions.PodStatusFunc == nil {
			return fmt.Errorf("kill pod options are required if update type is kill")
		}
		apiPodStatus := killPodOptions.PodStatusFunc(pod, podStatus)
		kl.statusManager.SetPodStatus(pod, apiPodStatus)
		// we kill the pod with the specified grace period since this is a termination
		if err := kl.killPod(pod, nil, podStatus, killPodOptions.PodTerminationGracePeriodSecondsOverride); err != nil {
			kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToKillPod, "error killing pod: %v", err)
			// there was an error killing the pod, so we return that error directly
			utilruntime.HandleError(err)
			return err
		}
		return nil
	}
    ....
    // 是否能运行pod
	runnable := kl.canRunPod(pod)
	if !runnable.Admit {
		//不能回写container等待原因
		apiPodStatus.Reason = runnable.Reason
		apiPodStatus.Message = runnable.Message
		// Waiting containers are not creating.
		const waitingReason = "Blocked"
		for _, cs := range apiPodStatus.InitContainerStatuses {
			if cs.State.Waiting != nil {
				cs.State.Waiting.Reason = waitingReason
			}
		}
		for _, cs := range apiPodStatus.ContainerStatuses {
			if cs.State.Waiting != nil {
				cs.State.Waiting.Reason = waitingReason
			}
		}
	}

	// 更新statusManager pod状态
	kl.statusManager.SetPodStatus(pod, apiPodStatus)

	// 校验失败、标记删除、pod失败则kill pod
	if !runnable.Admit || pod.DeletionTimestamp != nil || apiPodStatus.Phase == v1.PodFailed {
		var syncErr error
		if err := kl.killPod(pod, nil, podStatus, nil); err != nil {
			kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToKillPod, "error killing pod: %v", err)
			syncErr = fmt.Errorf("error killing pod: %v", err)
			utilruntime.HandleError(syncErr)
		} else {
			if !runnable.Admit {
				// There was no error killing the pod, but the pod cannot be run.
				// Return an error to signal that the sync loop should back off.
				syncErr = fmt.Errorf("pod cannot be run: %s", runnable.Message)
			}
		}
		return syncErr
	}

	// network plugin是否ready
	if err := kl.runtimeState.networkErrors(); err != nil && !kubecontainer.IsHostNetworkPod(pod) {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.NetworkNotReady, "%s: %v", NetworkNotReadyErrorMsg, err)
		return fmt.Errorf("%s: %v", NetworkNotReadyErrorMsg, err)
	}

	// pod crgoup创建
	pcm := kl.containerManager.NewPodContainerManager()
	// 检查pod是否已经Terminate
	if !kl.podIsTerminated(pod) {
		// When the kubelet is restarted with the cgroups-per-qos
		// flag enabled, all the pod's running containers
		// should be killed intermittently and brought back up
		// under the qos cgroup hierarchy.
		// Check if this is the pod's first sync
		firstSync := true
		for _, containerStatus := range apiPodStatus.ContainerStatuses {
			if containerStatus.State.Running != nil {
				firstSync = false
				break
			}
		}
		// Don't kill containers in pod if pod's cgroups already
		// exists or the pod is running for the first time
		podKilled := false
		if !pcm.Exists(pod) && !firstSync {
			if err := kl.killPod(pod, nil, podStatus, nil); err == nil {
				podKilled = true
			}
		}
		// Create and Update pod's Cgroups
		// Don't create cgroups for run once pod if it was killed above
		// The current policy is not to restart the run once pods when
		// the kubelet is restarted with the new flag as run once pods are
		// expected to run only once and if the kubelet is restarted then
		// they are not expected to run again.
		// We don't create and apply updates to cgroup if its a run once pod and was killed above
		if !(podKilled && pod.Spec.RestartPolicy == v1.RestartPolicyNever) {
			if !pcm.Exists(pod) {
				if err := kl.containerManager.UpdateQOSCgroups(); err != nil {
					klog.V(2).Infof("Failed to update QoS cgroups while syncing pod: %v", err)
				}
				if err := pcm.EnsureExists(pod); err != nil {
					kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToCreatePodContainer, "unable to ensure pod container exists: %v", err)
					return fmt.Errorf("failed to ensure that the pod: %v cgroups exist and are correctly applied: %v", pod.UID, err)
				}
			}
		}
	}

	// 如果是mirrorPod进入mirrorPod处理逻辑
	if kubetypes.IsStaticPod(pod) {
		podFullName := kubecontainer.GetPodFullName(pod)
		deleted := false
		if mirrorPod != nil {
			if mirrorPod.DeletionTimestamp != nil || !kl.podManager.IsMirrorPodOf(mirrorPod, pod) {
				// The mirror pod is semantically different from the static pod. Remove
				// it. The mirror pod will get recreated later.
				klog.Infof("Trying to delete pod %s %v", podFullName, mirrorPod.ObjectMeta.UID)
				var err error
				deleted, err = kl.podManager.DeleteMirrorPod(podFullName, &mirrorPod.ObjectMeta.UID)
				if deleted {
					klog.Warningf("Deleted mirror pod %q because it is outdated", format.Pod(mirrorPod))
				} else if err != nil {
					klog.Errorf("Failed deleting mirror pod %q: %v", format.Pod(mirrorPod), err)
				}
			}
		}
		if mirrorPod == nil || deleted {
			node, err := kl.GetNode()
			if err != nil || node.DeletionTimestamp != nil {
				klog.V(4).Infof("No need to create a mirror pod, since node %q has been removed from the cluster", kl.nodeName)
			} else {
				klog.V(4).Infof("Creating a mirror pod for static pod %q", format.Pod(pod))
				if err := kl.podManager.CreateMirrorPod(pod); err != nil {
					klog.Errorf("Failed creating a mirror pod for %q: %v", format.Pod(pod), err)
				}
			}
		}
	}

	// 准备pod文件目录
	if err := kl.makePodDataDirs(pod); err != nil {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToMakePodDataDirectories, "error making pod data directories: %v", err)
		klog.Errorf("Unable to make pod data directories for pod %q: %v", format.Pod(pod), err)
		return err
	}

	// 等待挂载volumes
	if !kl.podIsTerminated(pod) {
		// Wait for volumes to attach/mount
		if err := kl.volumeManager.WaitForAttachAndMount(pod); err != nil {
			kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedMountVolume, "Unable to attach or mount volumes: %v", err)
			klog.Errorf("Unable to attach or mount volumes for pod %q: %v; skipping pod", format.Pod(pod), err)
			return err
		}
	}

	// Fetch the pull secrets for the pod
	pullSecrets := kl.getPullSecretsForPod(pod)

	// 调用runtime处理pod
	result := kl.containerRuntime.SyncPod(pod, podStatus, pullSecrets, kl.backOff)
	kl.reasonCache.Update(pod.UID, result)
	if err := result.Error(); err != nil {
		// Do not return error if the only failures were pods in backoff
		for _, r := range result.SyncResults {
			if r.Error != kubecontainer.ErrCrashLoopBackOff && r.Error != images.ErrImagePullBackOff {
				// Do not record an event here, as we keep all event logging for sync pod failures
				// local to container runtime so we get better errors
				return err
			}
		}
		return nil
	}
	return nil
}
```

