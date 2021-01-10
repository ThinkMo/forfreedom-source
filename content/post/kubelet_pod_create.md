+++
keywords = ["k8s", 'kubelet']
title = "kubelet源码解析-创建与删除POD(下)"
categories = ["k8s"]
disqusIdentifier = "k8s_kubelet_source"
comments = true
clearReading = true
date = 2021-01-08T15:59:30+08:00 
showSocial = false
showPagination = true
showTags = true
showDate = true
+++

### kubeGenericRuntimeManager

kubeGenericRuntimeManager为kubelet提供Runtime接口, 管理pods与containers生命周期, 调用remote runtime api完成操作；Kubelet与CRI交互如下图

![cri](/images/cri.png)

### SyncPod

接上文Pod处理走到调用kubeGenericRuntimeManager.SyncPod

pkg/kubelet/kuberuntime/kuberuntime_manager.go:661

```
func (m *kubeGenericRuntimeManager) SyncPod(pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) (result kubecontainer.PodSyncResult) {
	// 获得sandbox、container changes
	podContainerChanges := m.computePodActions(pod, podStatus)
	......
	// kill pod
	if podContainerChanges.KillPod {
	    .......
	    // 先停止pod中所有conatiners，执行preStop，再停止sandbox
		killResult := m.killPodWithSyncResult(pod, kubecontainer.ConvertPodStatusToRunningPod(m.runtimeName, podStatus), nil)
		result.AddPodSyncResult(killResult)
		if killResult.Error() != nil {
			klog.Errorf("killPodWithSyncResult failed: %v", killResult.Error())
			return
		}
		// 如果新建sandbox则清楚init containers
		if podContainerChanges.CreateSandbox {
			m.purgeInitContainers(pod, podStatus)
		}
	} else {
		// kill掉列表中所有containers，主要是处于未知状态的containers
		for containerID, containerInfo := range podContainerChanges.ContainersToKill {
			klog.V(3).Infof("Killing unwanted container %q(id=%q) for pod %q", containerInfo.name, containerID, format.Pod(pod))
			killContainerResult := kubecontainer.NewSyncResult(kubecontainer.KillContainer, containerInfo.name)
			result.AddSyncResult(killContainerResult)
			if err := m.killContainer(pod, containerID, containerInfo.name, containerInfo.message, nil); err != nil {
				killContainerResult.Fail(kubecontainer.ErrKillContainer, err.Error())
				klog.Errorf("killContainer %q(id=%q) for pod %q failed: %v", containerInfo.name, containerID, format.Pod(pod), err)
				return
			}
		}
	}
	......
	// 创建sandbox
	podSandboxID := podContainerChanges.SandboxID
	if podContainerChanges.CreateSandbox {
		var msg string
		var err error

		klog.V(4).Infof("Creating PodSandbox for pod %q", format.Pod(pod))
		createSandboxResult := kubecontainer.NewSyncResult(kubecontainer.CreatePodSandbox, format.Pod(pod))
		result.AddSyncResult(createSandboxResult)
		// 创建sandbox配置、日志目录，调用runtime runSandbox
		podSandboxID, msg, err = m.createPodSandbox(pod, podContainerChanges.Attempt)
		......
	}
	podIP := ""
	if len(podIPs) != 0 {
		podIP = podIPs[0]
	}
	configPodSandboxResult := kubecontainer.NewSyncResult(kubecontainer.ConfigPodSandbox, podSandboxID)
	result.AddSyncResult(configPodSandboxResult)
	// 为container运行生成sandbox config配置，如dns、hostname、端口映射等
	podSandboxConfig, err := m.generatePodSandboxConfig(pod, podContainerChanges.Attempt)
	if err != nil {
		message := fmt.Sprintf("GeneratePodSandboxConfig for pod %q failed: %v", format.Pod(pod), err)
		klog.Error(message)
		configPodSandboxResult.Fail(kubecontainer.ErrConfigPodSandbox, message)
		return
	}
	// 启动container函数
	start := func(typeName string, spec *startSpec) error {
		// 拉取镜像，创建并启动container，执行post start hook
		if msg, err := m.startContainer(podSandboxID, podSandboxConfig, spec, pod, podStatus, pullSecrets, podIP, podIPs); err != nil {......}
		return nil
	}

	// 启动临时container
	if utilfeature.DefaultFeatureGate.Enabled(features.EphemeralContainers) {
		for _, idx := range podContainerChanges.EphemeralContainersToStart {
			start("ephemeral container", ephemeralContainerStartSpec(&pod.Spec.EphemeralContainers[idx]))
		}
	}

	// 启动init container
	if container := podContainerChanges.NextInitContainerToStart; container != nil {
		// Start the next init container.
		if err := start("init container", containerStartSpec(container)); err != nil {
			return
		}
		// Successfully started the container; clear the entry in the failure
		klog.V(4).Infof("Completed init container %q for pod %q", container.Name, format.Pod(pod))
	}

	// 启动队列中的containers
	for _, idx := range podContainerChanges.ContainersToStart {
		start("container", containerStartSpec(&pod.Spec.Containers[idx]))
	}

	return
}
```

**SyncPod** 

1. 对比pod、podStatus获得pod、container改变的podContainerChanges
2. 根据podContainerChanges处理已改变的Pod
3. 如果有Pod需要kill，则调用m.killPodWithSyncResult，如果有container需要kill调用m.killContainer
4. 如果有Pod需要创建，先创建sandbox、之后是临时container、init container 最后启动container

### computePodActions

pkg/kubelet/kuberuntime/kuberuntime_manager.go:480

```
func (m *kubeGenericRuntimeManager) computePodActions(pod *v1.Pod, podStatus *kubecontainer.PodStatus) podActions {
    // 判断是否需要新建sandbox，sandbox ready数量!=1、sandbox network namespace change、sandbox 没有ip会重建sandbox
	createPodSandbox, attempt, sandboxID := m.podSandboxChanged(pod, podStatus)
	changes := podActions{
		KillPod:           createPodSandbox,
		CreateSandbox:     createPodSandbox,
		SandboxID:         sandboxID,
		Attempt:           attempt,
		ContainersToStart: []int{},
		ContainersToKill:  make(map[kubecontainer.ContainerID]containerToKillInfo),
	}
	// 需新建sandbox
	if createPodSandbox {
		if !shouldRestartOnFailure(pod) && attempt != 0 && len(podStatus.ContainerStatuses) != 0 {
			// pod存在、containers done不需要创建sandbox
			changes.CreateSandbox = false
			return changes
		}
		// 获取需要启动的container
		var containersToStart []int
		for idx, c := range pod.Spec.Containers {
			if pod.Spec.RestartPolicy == v1.RestartPolicyOnFailure && containerSucceeded(&c, podStatus) {
				continue
			}
			containersToStart = append(containersToStart, idx)
		}
		// 没有container的pod不需要创建sandbox
		if len(containersToStart) == 0 {
			_, _, done := findNextInitContainerToRun(pod, podStatus)
			if done {
				changes.CreateSandbox = false
				return changes
			}
		}
		// 如果有initContainers 加入到podActions
		if len(pod.Spec.InitContainers) != 0 {
			// Pod has init containers, return the first one.
			changes.NextInitContainerToStart = &pod.Spec.InitContainers[0]
			return changes
		}
		changes.ContainersToStart = containersToStart
		return changes
	}
	// 找到init containers
	initLastStatus, next, done := findNextInitContainerToRun(pod, podStatus)
	// 处理未完成的init containers
	if !done {
		if next != nil {
			initFailed := initLastStatus != nil && isInitContainerFailed(initLastStatus)
			// 如果fail并且restartonfailure则需要置位killPod
			if initFailed && !shouldRestartOnFailure(pod) {
				changes.KillPod = true
			} else {
				// 将未知状态container加入start队列
				if initLastStatus != nil && initLastStatus.State == kubecontainer.ContainerStateUnknown {
					changes.ContainersToKill[initLastStatus.ID] = containerToKillInfo{
						name:      next.Name,
						container: next,
						message: fmt.Sprintf("Init container is in %q state, try killing it before restart",
							initLastStatus.State),
					}
				}
				changes.NextInitContainerToStart = next
			}
		}
		return changes
	}
	keepCount := 0
	// 遍历检查container的状态
	for idx, container := range pod.Spec.Containers {
		containerStatus := podStatus.FindContainerStatusByName(container.Name)
		// 调用postStop hook，加快资源分配
		if containerStatus != nil && containerStatus.State != kubecontainer.ContainerStateRunning {
			if err := m.internalLifecycle.PostStopContainer(containerStatus.ID.ID); err != nil {
				klog.Errorf("internal container post-stop lifecycle hook failed for container %v in pod %v with error %v",
					container.Name, pod.Name, err)
			}
		}
		// 如果container不存在，或则不再running状态，根据状态、restartPolicy决定是否重启
		if containerStatus == nil || containerStatus.State != kubecontainer.ContainerStateRunning {
			if kubecontainer.ShouldContainerBeRestarted(&container, pod, podStatus) {
				message := fmt.Sprintf("Container %+v is dead, but RestartPolicy says that we should restart it.", container)
				klog.V(3).Infof(message)
				changes.ContainersToStart = append(changes.ContainersToStart, idx)
				// 未知状态container需要kill后重启
				if containerStatus != nil && containerStatus.State == kubecontainer.ContainerStateUnknown {
					changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
						name:      containerStatus.Name,
						container: &pod.Spec.Containers[idx],
						message: fmt.Sprintf("Container is in %q state, try killing it before restart",
							containerStatus.State),
					}
				}
			}
			continue
		}
		// 容器当前状态为running，但满足以下条件需要重启
		var message string
		// policy是否为RestartNever
		restart := shouldRestartOnFailure(pod)
		// 通过对比hash，container spec变了则需要重启
		if _, _, changed := containerChanged(&container, containerStatus); changed {
			message = fmt.Sprintf("Container %s definition changed", container.Name)
			// Restart regardless of the restart policy because the container
			// spec changed.
			restart = true
		// liveness检查，失败需要kill，不需重启
		} else if liveness, found := m.livenessManager.Get(containerStatus.ID); found && liveness == proberesults.Failure {
			// If the container failed the liveness probe, we should kill it.
			message = fmt.Sprintf("Container %s failed liveness probe", container.Name)
		// startup探针失败，需要kill，不需重启
		} else if startup, found := m.startupManager.Get(containerStatus.ID); found && startup == proberesults.Failure {
			// If the container failed the startup probe, we should kill it.
			message = fmt.Sprintf("Container %s failed startup probe", container.Name)
		} else {
			// 其他不需要重启
			keepCount++
			continue
		}
		// 处理需重启或kill的container
		// 需要重启的加入重启队列，在被调用函数中总是先kill再start
		if restart {
			message = fmt.Sprintf("%s, will be restarted", message)
			changes.ContainersToStart = append(changes.ContainersToStart, idx)
		}
		// 添加需要kill的container
		changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
			name:      containerStatus.Name,
			container: &pod.Spec.Containers[idx],
			message:   message,
		}
		klog.V(2).Infof("Container %q (%q) of pod %s: %s", container.Name, containerStatus.ID, format.Pod(pod), message)
	}
	if keepCount == 0 && len(changes.ContainersToStart) == 0 {
		changes.KillPod = true
	}
	return changes
}
```

**computePodActions**  依此检查sandbox、init container、container的状态，返回变更列表；在SyncPod中是先处理kill Pod再执行创建，所以在重启列表中会的也会加入kill队列


### 创建Pod(createPodSandbox与startContainer)

```
Kubelet                  KubeletGenericRuntimeManager       RemoteRuntime
   +                              +                               +
   |                              |                               |
   +---------SyncPod------------->+                               |
   |                              |                               |
   |                              +---- Create PodSandbox ------->+
   |                              +<------------------------------+
   |                              |                               |
   |                              XXXXXXXXXXXX                    |
   |                              |          X                    |
   |                              |    NetworkPlugin.             |
   |                              |       SetupPod                |
   |                              |          X                    |
   |                              XXXXXXXXXXXX                    |
   |                              |                               |
   |                              +<------------------------------+
   |                              +----    Pull image1   -------->+
   |                              +<------------------------------+
   |                              +---- Create container1 ------->+
   |                              +<------------------------------+
   |                              +---- Start container1 -------->+
   |                              +<------------------------------+
   |                              |                               |
   |                              +<------------------------------+
   |                              +----    Pull image2   -------->+
   |                              +<------------------------------+
   |                              +---- Create container2 ------->+
   |                              +<------------------------------+
   |                              +---- Start container2 -------->+
   |                              +<------------------------------+
   |                              |                               |
   | <-------Success--------------+                               |
   |                              |                               |
   +                              +                               +
```

- createPodSandbox

sandbox(沙箱)是一种程序隔离运行机制，为了安全在限定权限下的运行环境；在k8s中可以理解为pause容器，pause容器是pod共享cgroup、namespace的基础

pkg/kubelet/kuberuntime/kuberuntime_sandbox.go:38

```
func (m *kubeGenericRuntimeManager) createPodSandbox(pod *v1.Pod, attempt uint32) (string, string, error) {
	// 生成pod sandbox配置，包括DNS、hostname、pod log dir、端口映射
	podSandboxConfig, err := m.generatePodSandboxConfig(pod, attempt)
	if err != nil {
		message := fmt.Sprintf("GeneratePodSandboxConfig for pod %q failed: %v", format.Pod(pod), err)
		klog.Error(message)
		return "", message, err
	}
	// 根据sandbox配置创建日志目录
	err = m.osInterface.MkdirAll(podSandboxConfig.LogDirectory, 0755)
	if err != nil {
		message := fmt.Sprintf("Create pod log directory for pod %q failed: %v", format.Pod(pod), err)
		klog.Errorf(message)
		return "", message, err
	}
	runtimeHandler := ""
	if utilfeature.DefaultFeatureGate.Enabled(features.RuntimeClass) && m.runtimeClassManager != nil {
		runtimeHandler, err = m.runtimeClassManager.LookupRuntimeHandler(pod.Spec.RuntimeClassName)
		if err != nil {
			message := fmt.Sprintf("CreatePodSandbox for pod %q failed: %v", format.Pod(pod), err)
			return "", message, err
		}
		if runtimeHandler != "" {
			klog.V(2).Infof("Running pod %s with RuntimeHandler %q", format.Pod(pod), runtimeHandler)
		}
	}
	// 通过runtimeClient启动sandbox，network在这里会设置好
	podSandBoxID, err := m.runtimeService.RunPodSandbox(podSandboxConfig, runtimeHandler)
	if err != nil {
		message := fmt.Sprintf("CreatePodSandbox for pod %q failed: %v", format.Pod(pod), err)
		klog.Error(message)
		return "", message, err
	}

	return podSandBoxID, "", nil
}
```
**createPodSandbox** 函数

1  生成pod sandbox配置，包括DNS、hostname、log dir、端口映射，以及generatePodSandboxLinuxConfig中的cgroup、sysctls、namespace、linux权限；

2  根据配置创建日志目录/var/log/pods/...

3  调用runtimeService借口启动sandbox


- startContainer

pkg/kubelet/kuberuntime/kuberuntime_container.go:134

```
func (m *kubeGenericRuntimeManager) startContainer(podSandboxID string, podSandboxConfig *runtimeapi.PodSandboxConfig, spec *startSpec, pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, podIP string, podIPs []string) (string, error) {
	container := spec.container
	// 拉取镜像
	imageRef, msg, err := m.imagePuller.EnsureImageExists(pod, container, pullSecrets, podSandboxConfig)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return msg, err
	}
	// 更新restartCount
	restartCount := 0
	containerStatus := podStatus.FindContainerStatusByName(container.Name)
	if containerStatus != nil {
		restartCount = containerStatus.RestartCount + 1
	}
	target, err := spec.getTargetID(podStatus)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainerConfig
	}
	// 生成容器配置
	containerConfig, cleanupAction, err := m.generateContainerConfig(container, pod, restartCount, podIP, imageRef, podIPs, target)
	if cleanupAction != nil {
		defer cleanupAction()
	}
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainerConfig
	}
	// 调用接口创建容器
	containerID, err := m.runtimeService.CreateContainer(podSandboxID, containerConfig, podSandboxConfig)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainer
	}
	// 容器启动前初始化，主要是cpuManager亲和性加入等
	err = m.internalLifecycle.PreStartContainer(pod, container, containerID)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToStartContainer, "Internal PreStartContainer hook failed: %v", s.Message())
		return s.Message(), ErrPreStartHook
	}
	m.recordContainerEvent(pod, container, containerID, v1.EventTypeNormal, events.CreatedContainer, fmt.Sprintf("Created container %s", container.Name))
	// 启动容器
	err = m.runtimeService.StartContainer(containerID)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToStartContainer, "Error: %v", s.Message())
		return s.Message(), kubecontainer.ErrRunContainer
	}
	m.recordContainerEvent(pod, container, containerID, v1.EventTypeNormal, events.StartedContainer, fmt.Sprintf("Started container %s", container.Name))
	// 执行post hook
	if container.Lifecycle != nil && container.Lifecycle.PostStart != nil {
		kubeContainerID := kubecontainer.ContainerID{
			Type: m.runtimeName,
			ID:   containerID,
		}
		msg, handlerErr := m.runner.Run(kubeContainerID, pod, container, container.Lifecycle.PostStart)
		if handlerErr != nil {
			m.recordContainerEvent(pod, container, kubeContainerID.ID, v1.EventTypeWarning, events.FailedPostStartHook, msg)
			// 执行失败需要kill container
			if err := m.killContainer(pod, kubeContainerID, container.Name, "FailedPostStartHook", nil); err != nil {
				klog.Errorf("Failed to kill container %q(id=%q) in pod %q: %v, %v",
					container.Name, kubeContainerID.String(), format.Pod(pod), ErrPostStartHook, err)
			}
			return msg, fmt.Errorf("%s: %v", ErrPostStartHook, handlerErr)
		}
	}

	return "", nil
}
```

**startContainer**  负责拉取镜像、根据生成的容器配置创建容器，调用启动前hook，然后启动容器，执行postStart hook

### 删除Pod(killPodWithSyncResult与killContainer

```
Kubelet                  KubeletGenericRuntimeManager      RemoteRuntime
   +                              +                               +
   |                              |                               |
   +---------SyncPod------------->+                               |
   |                              |                               |
   |                              +----   Stop container1   ----->+
   |                              +<------------------------------+
   |                              +----  Delete container1  ----->+
   |                              +<------------------------------+
   |                              |                               |
   |                              +----   Stop container2   ------>+
   |                              +<------------------------------+
   |                              +----  Delete container2  ------>+
   |                              +<------------------------------+
   |                              |                               |
   |                              XXXXXXXXXXXX                    |
   |                              |          X                    |
   |                              |    NetworkPlugin.             |
   |                              |       TeardownPod             |
   |                              |          X                    |
   |                              XXXXXXXXXXXX                    |
   |                              |                               |
   |                              |                               |
   |                              +---- Delete PodSandbox  ------>+
   |                              +<------------------------------+
   |                              |                               |
   | <-------Success--------------+                               |
   |                              |                               |
   +                              +                               +
```

分两种情况，一种是sandbox改变走killPodWithSyncResult，一种是kill container走killContainer而sandbox不变

- killPodWithSyncResult 

pkg/kubelet/kuberuntime/kuberuntime_manager.go:896

```
func (m *kubeGenericRuntimeManager) killPodWithSyncResult(pod *v1.Pod, runningPod kubecontainer.Pod, gracePeriodOverride *int64) (result kubecontainer.PodSyncResult) {
	// 遍历pod container调用killContainer并等待容器停止
	killContainerResults := m.killContainersWithSyncResult(pod, runningPod, gracePeriodOverride)
	for _, containerResult := range killContainerResults {
		result.AddSyncResult(containerResult)
	}
	killSandboxResult := kubecontainer.NewSyncResult(kubecontainer.KillPodSandbox, runningPod.ID)
	result.AddSyncResult(killSandboxResult)
	// 停止所有sandbox
	for _, podSandbox := range runningPod.Sandboxes {
		// pod network在这里被清理
		if err := m.runtimeService.StopPodSandbox(podSandbox.ID.ID); err != nil {
			killSandboxResult.Fail(kubecontainer.ErrKillPodSandbox, err.Error())
			klog.Errorf("Failed to stop sandbox %q", podSandbox.ID)
		}
	}

	return
}
```

**killPodWithSyncResult** 会先遍历pod container 等待完成kill containers，再调用runtimeService停止sandbox

- killContainer

pkg/kubelet/kuberuntime/kuberuntime_container.go:587

```
func (m *kubeGenericRuntimeManager) killContainer(pod *v1.Pod, containerID kubecontainer.ContainerID, containerName string, message string, gracePeriodOverride *int64) error {
	// 获取containerSpec
	var containerSpec *v1.Container
	if pod != nil {
		if containerSpec = kubecontainer.GetContainerSpec(pod, containerName); containerSpec == nil {
			return fmt.Errorf("failed to get containerSpec %q(id=%q) in pod %q when killing container for reason %q",
				containerName, containerID.String(), format.Pod(pod), message)
		}
	} else {
		// Restore necessary information if one of the specs is nil.
		restoredPod, restoredContainer, err := m.restoreSpecsFromContainerLabels(containerID)
		if err != nil {
			return err
		}
		pod, containerSpec = restoredPod, restoredContainer
	}
	// 优雅停止
	gracePeriod := int64(minimumGracePeriodInSeconds)
	switch {
	case pod.DeletionGracePeriodSeconds != nil:
		gracePeriod = *pod.DeletionGracePeriodSeconds
	case pod.Spec.TerminationGracePeriodSeconds != nil:
		gracePeriod = *pod.Spec.TerminationGracePeriodSeconds
	}
	......
	// 执行preStop
	if err := m.internalLifecycle.PreStopContainer(containerID.ID); err != nil {
		return err
	}
	if containerSpec.Lifecycle != nil && containerSpec.Lifecycle.PreStop != nil && gracePeriod > 0 {
		gracePeriod = gracePeriod - m.executePreStopHook(pod, containerID, containerSpec, gracePeriod)
	}
	if gracePeriod < minimumGracePeriodInSeconds {
		gracePeriod = minimumGracePeriodInSeconds
	}
	if gracePeriodOverride != nil {
		gracePeriod = *gracePeriodOverride
		klog.V(3).Infof("Killing container %q, but using a %d second grace period override", containerID, gracePeriod)
	}
	klog.V(2).Infof("Killing container %q with a %d second grace period", containerID.String(), gracePeriod)
	// 调用接口停止容器
	err := m.runtimeService.StopContainer(containerID.ID, gracePeriod)
	if err != nil {
		klog.Errorf("Container %q termination failed with gracePeriod %d: %v", containerID.String(), gracePeriod, err)
	} else {
		klog.V(3).Infof("Container %q exited normally", containerID.String())
	}
	return err
}
```

**killContainer**  先执行preStop hook再通过runtimeService停止容器

以上是Kubelet创建删除POD的主流程，之后是通过CRI  RuntimeService完成容器的创建与删除，具体说明可以参考[Introducing Container Runtime Interface (CRI) in Kubernetes](https://kubernetes.io/blog/2016/12/container-runtime-interface-cri-in-kubernetes/)，[SPEC](https://github.com/opencontainers/runtime-spec)；其中比较特殊的是dockershim其相当于实现了一个cantainer runtime server，有机会可以深入看下dockershim的实现。
