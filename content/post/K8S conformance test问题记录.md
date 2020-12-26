+++
keywords = ["k8s", 'conformance', 'test']
title = "k8s conformance test问题记录"
categories = ["k8s"]
disqusIdentifier = "k8sconformancetest"
comments = true
clearReading = true
date = 2020-12-25T17:03:30+08:00 
showSocial = false
showPagination = true
showTags = true
showDate = true
+++

## K8S conformance test问题记录

K8S conformance test步骤与提交可以参考[这里](https://github.com/cncf/k8s-conformance/blob/master/instructions.md), 本文主要记录相关问题

### 私有云环境测试镜像准备

在隔离的私有云环境跑测试，需要将K8S conformance test需要的镜像提前准备好并存储到私有镜像仓库中

```
1. 获取所有测试镜像
sonobuoy images --kubernetes-version v1.19.3 > images   #我这里是v1.19.3版本k8s，可以替换

2. 在非离线环境中下载镜像包
for i in `cat images`; do docker pull $i ;done
docker save `cat image | tr "\n" " "` -o images.tar

3. 在离线环境加载镜像包
docker load -i images.tar

4. 生成e2e repo配置，并将所有配置都替换为私有镜像仓库地址
sonobuoy gen default-image-config > repo.yaml

5. push镜像
sonobuoy images push --e2e-repo-config repo.yaml
```

### 使用私有镜像仓库测试

```
开始测试
registry_url=xx
sonobuoy run --mode=certified-conformance --sonobuoy-image $registry_url/sonobuoy:v0.20.0 --kube-conformance-image $registry_url/conformance:v1.19.3 --systemd-logs-image $registry_url/systemd-logs:v0.3 --e2e-repo-config repo.yaml

sonobuoy status --json | jq 可以查看状态
```

### 失败用例排查

对于失败的用例只能查看e2e日志结合起来分析问题

```
检出结果
outfile=$(sonobuoy retrieve) && mkdir ./results; tar xzf $outfile -C ./results
查看失败用例
sonobuoy e2e 202012250222_sonobuoy_427ee6d7-ab87-4e85-ba71-1d0754828c92.tar.gz

根据失败用例查看日志分析results/plugins/e2e/results/global/e2e.log
```

小技巧: 可以跑单个用例查看结果验证，例如下面单独测试"KubeletManagedEtcHosts should test kubelet managed /etc/hosts file"

```
sonobuoy run  --e2e-focus="KubeletManagedEtcHosts should test kubelet managed /etc/hosts file" --sonobuoy-image $registry_url/sonobuoy:v0.20.0 --kube-conformance-image $registry_url/conformance:v1.19.3 --systemd-logs-image $registry_url/systemd-logs:v0.3 --e2e-repo-config repo.yaml
```

这次测试有3个test case失败如下

```
    "failures": [
      "[sig-network] Networking Granular Checks: Pods should function for node-pod communication: udp [LinuxOnly] [NodeConformance] [Conformance]",
      "[sig-network] Networking Granular Checks: Pods should function for node-pod communication: http [LinuxOnly] [NodeConformance] [Conformance]",
      "[k8s.io] KubeletManagedEtcHosts should test kubelet managed /etc/hosts file [LinuxOnly] [NodeConformance] [Conformance]"
    ]
```

分析日志与失败代码test/e2e/framework/exec_util.go 可以看到是apiserver 403拒绝

最后通过修改apiserver参数 --enable-admission-plugins 去掉  DenyEscalatingExec 解决，具体参数说明看[这里](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#denyescalatingexec)

单独跑这3个测试通过后可以全部测试一遍，后面就可以提交了
