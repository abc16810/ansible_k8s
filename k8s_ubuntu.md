



###  系统
| IP | 主机名|系统 |节点|
|---|---|---|---|
192.168.119.22|master01|Ubuntu20.4| etcd apiserver controller shceduler ingress|
192.168.119.23|node01|Ubuntu20.4|etcd|
192.168.119.24|node02|Ubuntu20.4|etcd|
192.168.119.25|node03|Ubuntu20.4|jenkins harbor|

### 组件版本

- kubernetes v1.27.5
- etcd v3.5.7
- containerd v1.7.5
- cni-plugins v1.3.0
- nerdctl v1.5.0
- crictl 1.27.0
- calico v3.25.2
- coredns v1.14.0
- Helm v3.11.1
- metrics-server 0.6.4
- ingress-nginx 1.8.2
- jenkins:2.414.1-lts
- harbor 2.9.0


#### 初始化服务器
- 设置主机名配置hosts文件
- 关闭防火墙
- 关闭swap


#### etcd集群部署

略

### 安装kubernetes组件

#### 控制平面

下载安装包。二进制包所在的 github 地址如下
```
wget https://dl.k8s.io/v1.27.5/kubernetes-server-linux-amd64.tar.gz
tar -zxvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes/server/bin/
cp kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/local/bin/ 
```

##### 部署apiserver
```
# 创建配置和日志目录
mkdir -p /etc/kubernetes/ssl
```
1、创建 token.csv 文件
```
[root@master01 work]# cd /etc/kubernetes/ 
[root@master01 work]# cat > token.csv << EOF
$(head -c 16 /dev/urandom | od -An -t x | tr -d ' '),kubelet-bootstrap,10001,"system:bootstrappers"
EOF
```

2、创建kube-apiserver 证书 （略）
```
# 确保存在如下证书
ll /etc/kubernetes/ssl/
drwxr-xr-x 2 root root 4096 Sep 12 07:37 ./
drwxr-xr-x 3 root root 4096 Sep 12 07:34 ../
-rw------- 1 root root 1679 Sep 12 07:37 ca-key.pem
-rw-r--r-- 1 root root 1326 Sep 12 07:37 ca.pem
-rw------- 1 root root 1679 Sep 12 07:37 kube-apiserver-key.pem
-rw-r--r-- 1 root root 1606 Sep 12 07:37 kube-apiserver.pem
```

3、创建 apiserver 配置文件
```
KUBE_APISERVER_OPTS="--v=2 \
--etcd-servers=https://192.168.119.22:2379,https://192.168.119.23:2379,https://192.168.119.24:2379 \
--bind-address=192.168.119.22 \
--secure-port=6443 \
--advertise-address=192.168.119.22 \
--anonymous-auth=false \
--allow-privileged=true \
--service-cluster-ip-range=10.0.0.0/16 \
--enable-admission-plugins=DefaultStorageClass,ServiceAccount,ResourceQuota,NodeRestriction \
--authorization-mode=RBAC,Node \
--enable-bootstrap-token-auth=true \
--runtime-config=api/all=true \
--token-auth-file=/etc/kubernetes/token.csv \
--service-node-port-range=30000-32767 \
--kubelet-client-certificate=/etc/kubernetes/ssl/kube-apiserver.pem \
--kubelet-client-key=/etc/kubernetes/ssl/kube-apiserver-key.pem \
--tls-cert-file=/etc/kubernetes/ssl/kube-apiserver.pem  \
--tls-private-key-file=/etc/kubernetes/ssl/kube-apiserver-key.pem \
--client-ca-file=/etc/kubernetes/ssl/ca.pem \
--service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \
--service-account-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \
--service-account-issuer=https://kubernetes.default.svc.cluster.local \
--etcd-cafile=/etc/etcd/ssl/ca.pem \
--etcd-certfile=/etc/etcd/ssl/etcd.pem \
--etcd-keyfile=/etc/etcd/ssl/etcd-key.pem \
--audit-log-maxage=30 \
--audit-log-maxbackup=3 \
--audit-log-maxsize=100 \
--event-ttl=1h \
--audit-log-path=/var/log/kube-apiserver-audit.log"
```
4、创建api服务启动文件
```
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=etcd.service
Wants=etcd.service
 
[Service]
EnvironmentFile=-/etc/kubernetes/kube-apiserver.conf
ExecStart=/usr/local/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536
 
[Install]
WantedBy=multi-user.target
```

5、启动kube-apiserver
```
systemctl daemon-reload && systemctl enable kube-apiserver && systemctl start kube-apiserver 

# 测试
root@master01:/etc/kubernetes# curl --insecure https://192.168.119.22:6443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```
##### 部署 kubectl (略)

`kubectl`是Kubernetes API 与Kubernetes 集群的控制面进行通信的命令行工具
```
# 单独下载地址 curl -LO https://dl.k8s.io/release/v1.27.5/bin/linux/amd64/kubectl
# kubectl version --client --output=yaml
clientVersion:
  buildDate: "2023-08-24T00:48:26Z"
  compiler: gc
  gitCommit: 93e0d7146fb9c3e9f68aa41b2b4265b2fcdb0a4c
  gitTreeState: clean
  gitVersion: v1.27.5
  goVersion: go1.20.7
  major: "1"
  minor: "27"
  platform: linux/amd64
kustomizeVersion: v5.0.1
```
针对配置信息，kubectl 在 `$HOME/.kube` 目录中查找一个名为 config 的配置文件
```
# 创建配置文件目录
mkdir /root/.kube
```
1、配置安全上下文
创建 kubeconfig 配置文件，kubeconfig 为 kubectl 的配置文件，包含访问 apiserver 的所有信息，如 apiserver 地址、 CA 证书和自身使用的证书
```
kubectl config set-cluster kubernetes --certificate-authority=ca.pem  --embed-certs=true --server=https://192.168.119.22:6443 --kubeconfig=kube.config
kubectl config set-credentials cluster-admin --client-certificate=admin.pem --client-key=admin-key.pem --embed-certs=true --kubeconfig=kube.config
kubectl config set-context default --cluster=kubernetes --user=cluster-admin  --kubeconfig=kube.config
kubectl config use-context default --kubeconfig=kube.config
```
2、查看集群组件状态
```
cp kube.config  /root/.kube/config

root@master01:/etc/kubernetes/ssl# kubectl cluster-info
Kubernetes control plane is running at https://192.168.119.22:6443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
root@master01:/etc/kubernetes/ssl# kubectl get componentstatuses 
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS      MESSAGE                                                                                        ERROR
controller-manager   Unhealthy   Get "https://127.0.0.1:10257/healthz": dial tcp 127.0.0.1:10257: connect: connection refused   
scheduler            Unhealthy   Get "https://127.0.0.1:10259/healthz": dial tcp 127.0.0.1:10259: connect: connection refused   
etcd-0               Healthy                                                                                                    
etcd-1               Healthy                                                                                                    
etcd-2               Healthy 
```
:warning: controller-manager 和 scheduler 还没部署 所以状态是不健康的

##### 部署 kube-controller-manager

1、生成证书
```
# /etc/kubernetes/ssl
kube-controller-manager-key.pem  kube-controller-manager.pem
```

2、创建kube-controller-manager配置文件
```
# kube-controller-manager.conf 
KUBE_CONTROLLER_MANAGER_OPTS="--secure-port=10257 \
  --bind-address=0.0.0.0 \
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \
  --service-cluster-ip-range=10.0.0.0/16 \
  --cluster-name=kubernetes \
  --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \
  --authorization-always-allow-paths=/healthz,/readyz,/livez,/metrics \
  --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --allocate-node-cidrs=true \
  --cluster-cidr=10.100.0.0/16 \
  --root-ca-file=/etc/kubernetes/ssl/ca.pem \
  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --leader-elect=true \
  --feature-gates=RotateKubeletServerCertificate=true \
  --controllers=*,bootstrapsigner,tokencleaner \
  --horizontal-pod-autoscaler-sync-period=10s \
  --tls-cert-file=/etc/kubernetes/ssl/kube-controller-manager.pem \
  --tls-private-key-file=/etc/kubernetes/ssl/kube-controller-manager-key.pem \
  --use-service-account-credentials=true \
  --cluster-signing-duration=43800h0m0s \
  --v=2"
```

3、创建kube-controller-manager启动文件

```
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/etc/kubernetes/kube-controller-manager.conf
ExecStart=/usr/local/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
```

4、生成 kube-controller-manager 的 kubeconfig文件 

```
# /etc/kubernetes
kubectl config set-cluster kubernetes --certificate-authority=ssl/ca.pem  --embed-certs=true --server=https://192.168.119.22:6443 --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-credentials  system:kube-controller-manager --client-certificate=ssl/kube-controller-manager.pem --client-key=ssl/kube-controller-manager-key.pem --embed-certs=true --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-context system:kube-controller-manager --cluster=kubernetes --user=system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
```
5、启动服务
```
systemctl daemon-reload  &&systemctl enable kube-controller-manager && systemctl start kube-controller-manager

root@master01:/etc/kubernetes# kubectl  get cs
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS      MESSAGE                                                                                        ERROR
scheduler            Unhealthy   Get "https://127.0.0.1:10259/healthz": dial tcp 127.0.0.1:10259: connect: connection refused   
controller-manager   Healthy     ok                                                                                             
etcd-0               Healthy                                                                                                    
etcd-2               Healthy                                                                                                    
etcd-1               Healthy
```
controller-manager 已经变成正常状态


##### 部署 kube-scheduler

1、生成证书
```
# /etc/kubernetes/ssl
kube-scheduler-key.pem  kube-scheduler.pem
```
2、生成 kube-scheduler 的 .kubeconfig 配置文件
```
kubectl config set-cluster kubernetes --certificate-authority=ssl/ca.pem  --embed-certs=true --server=https://192.168.119.22:6443 --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler --client-certificate=ssl/kube-scheduler.pem --client-key=ssl/kube-scheduler-key.pem --embed-certs=true --kubeconfig=kube-scheduler.kubeconfig
kubectl config set-context default --cluster=kubernetes --user=system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig
kubectl config use-context default --kubeconfig=kube-scheduler.kubeconfig
```
3、创建配置文件 kube-scheduler的配置文件
```
KUBE_SCHEDULER_OPTS="--bind-address=0.0.0.0 \
--kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \
--authorization-always-allow-paths=/healthz,/readyz,/livez,/metrics \
--leader-elect=true \
--v=2"

```
4、创建kube-scheduler的服务启动文件

```
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/etc/kubernetes/kube-scheduler.conf
ExecStart=/usr/local/bin/kube-scheduler \$KUBE_SCHEDULER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
```
5、启动服务
```
systemctl daemon-reload 
systemctl enable kube-scheduler
systemctl start kube-scheduler
systemctl status kube-scheduler

root@master01:/etc/kubernetes# kubectl get cs
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS    MESSAGE   ERROR
controller-manager   Healthy   ok        
scheduler            Healthy   ok        
etcd-1               Healthy             
etcd-0               Healthy             
etcd-2               Healthy
```

#### 工作节点

必须的组件：kubelet、kube-proxy

##### 安装 containerd

从`https://github.com/containerd/containerd/releases` 下载 `containerd-<VERSION>-<OS>-<ARCH>.tar.gz` 存档，解压到`/usr/local/bin`

1、解压
```
tar Cxzvf /usr/local containerd-1.7.5-linux-amd64.tar.gz
```
2、配置文件 /etc/containerd/config.toml
```
containerd config default > /etc/containerd/config.toml # 生成默认配置

# 配置 systemd cgroup 驱动
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  ...
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
    SystemdCgroup = true

# 将sandbox国内源
sandbox_image = "registry.k8s.io/pause:3.8"
修改为如下
sandbox_image = "registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.8"    
```

3、配置服务启动文件
```
从 https://github.com/containerd/containerd/blob/main/containerd.service 下载 containerd.service
```
4、启动
```
systemctl daemon-reload
systemctl enable --now containerd
```
5、安装runc
```
# 从 https://github.com/opencontainers/runc/releases 下载 
install -m 755 runc.amd64 /usr/local/sbin/runc

```
##### 安装CNI 插件
```
# cat /etc/containerd/config.toml 查看cni配置目录和bin文件目录
...
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"
# 创建
mkdir -p /opt/cni/bin
mkdir -p /etc/cni/net.d
# 从 https://github.com/containernetworking/plugins/releases 下载 cni-plugins-<OS>-<ARCH>-<VERSION>.tgz 存档，解压到 /opt/cni/bin 
tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v1.3.0.tgz
```
##### nerdctl
```
# https://github.com/containerd/nerdctl/releases
tar Cxzvvf /usr/local/bin nerdctl-1.5.0-linux-amd64.tar.gz
```

##### crictl

```
VERSION="v1.27.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz

cat /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: true
pull-image-on-create: false

```


##### 部署kubelet

1、创建配置文件
```
cat > /etc/kubernetes/kubelet.conf << EOF
KUBELET_OPTS="--v=2 \
--hostname-override=master01 \
--kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
--bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
--config=/etc/kubernetes/kubelet-config.yml \
--cert-dir=/etc/kubernetes/ssl \
--container-runtime-endpoint=unix:///run/containerd/containerd.sock"
EOF
```
2、配置参数文件kubelet-config.yml
```
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.119.22"
port: 10250  # 默认
readOnlyPort: 10255  # 默认
cgroupDriver: "systemd"
clusterDNS:
    - 10.0.0.2
clusterDomain: cluster.local
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/ssl/ca.pem
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
serializeImagePulls: false
evictionHard:
  imagefs.available: 15%
  memory.available: 200Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
```
3、生成bootstrap.kubeconfig文件
```
BOOTSTRAP_TOKEN=$(awk -F "," '{print $1}' /etc/kubernetes/token.csv)
kubectl config set-cluster kubernetes --certificate-authority=ssl/ca.pem --embed-certs=true --server=https://192.168.119.22:6443 --kubeconfig=bootstrap.kubeconfig
kubectl config set-credentials kubelet-bootstrap --token=${BOOTSTRAP_TOKEN} --kubeconfig=bootstrap.kubeconfig

kubectl config set-context default --cluster=kubernetes --user="kubelet-bootstrap" --kubeconfig=bootstrap.kubeconfig
kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

4、创建kubelet服务启动文件
```
cat > /usr/lib/systemd/system/kubelet.service << EOF
[Unit]
Description=Kubernetes Kubelet
After=docker.service

[Service]
EnvironmentFile=/etc/kubernetes/kubelet.conf
ExecStart=/usr/local/bin/kubelet \$KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```
5、启动
```
# 确保如下配置文件及启动文件存在
# /etc/kubernetes
bootstrap.kubeconfig  kubelet.conf  kubelet-config.yml
# /etc/kubernetes/ssl
ssl/ca-key.pem  ssl/ca.pem
# /usr/local/bin 二进制启动文件
kubelet kube-proxy

# 创建组和集群角色绑定
kubectl create clusterrolebinding bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap

systemctl daemon-reload && systemctl enable kubelet &&  systemctl start kubelet && systemctl status kubelet
```
6、批准kubelet证书申请并加入集群

```
# 查看kubelet证书请求
kubectl get csr
# 批准申请
kubectl certificate approve node-csr-QMFo4psx7Rifk9bFB8tRGpj4ZaVOVtPeifcZehablYs
[root@master01 cert]# kubectl get nodes
NAME     STATUS     ROLES    AGE   VERSION
node01   NotReady   <none>   26s   v1.25.0
# 注意：STATUS 是 NotReady 表示还没有安装网络插件
```

##### 部署 kube-proxy

1、生成证书
```
# /etc/kubernetes/ssl
kube-proxy-key.pem kube-proxy.pem
```
2、生成kubeconfig文件
```
kubectl config set-cluster kubernetes --certificate-authority=ssl/ca.pem --embed-certs=true --server=https://192.168.119.22:6443 --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy --client-certificate=ssl/kube-proxy.pem --client-key=ssl/kube-proxy-key.pem --embed-certs=true --kubeconfig=kube-proxy.kubeconfig
kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=kube-proxy.kubeconfig
kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```
3、创建kube-proxy-config.yml配置文件
```
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
bindAddress: 192.168.119.22
clusterCIDR: 10.100.0.0/24
healthzBindAddress: 192.168.119.22:10256
metricsBindAddress: 192.168.119.22:10249
clientConnection:
          kubeconfig: /etc/kubernetes/kube-proxy.kubeconfig
mode: "ipvs"
```

4、创建配置文件

```
cat > /etc/kubernetes/kube-proxy.conf << EOF
KUBE_PROXY_OPTS="--v=2 \\
--config=/etc/kubernetes/kube-proxy-config.yml"
EOF
```

6、创建kube-proxy服务启动文件
```
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/kube-proxy.conf
ExecStart=/usr/local/bin/kube-proxy $KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

6、启动
```
systemctl daemon-reload
systemctl start kube-proxy
systemctl enable kube-proxy
```

#### 网络CNI calico

1、安装Tigera Calico operator 和自定义资源定义

```
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.2/manifests/tigera-operator.yaml

```

2、配置`Installation`资源 启动网络

```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  # Configures Calico networking.
  calicoNetwork:
    # Note: The ipPools section cannot be modified post-install.
    ipPools:
    - blockSize: 24
      cidr: 10.100.0.0/16 
      encapsulation: VXLANCrossSubnet
      natOutgoing: Enabled
      nodeSelector: all()

    nodeAddressAutodetectionV4:
      interface: "ens.*"
```




#### 部署CoreDNS

```
https://github.com/coredns/deployment/blob/master/kubernetes/coredns.yaml.sed
[root@master02 ~]# ./deploy.sh -i 10.0.0.2 |kubectl apply -f -
serviceaccount/coredns created
clusterrole.rbac.authorization.k8s.io/system:coredns created
clusterrolebinding.rbac.authorization.k8s.io/system:coredns created
configmap/coredns created
deployment.apps/coredns created
service/kube-dns created
[root@master02 ~]# kubectl get pods -n kube-system
NAME                       READY   STATUS    RESTARTS   AGE
coredns-86cd448ddd-8nls5   1/1     Running   0          5m45s
```
修改文件配置

```
REVERSE_CIDRS ——>  in-addr.arpa ip6.arpa
CLUSTER_DOMAIN ——>  cluster.local
UPSTREAMNAMESERVER ——>  /etc/resolv.conf
CLUSTER_DNS_IP ——> 10.0.0.2
STUBDOMAINS  ——> ""
```

##### helm
Helm的每个版本都为各种操作系统提供了二进制版本。这些二进制版本可以手动下载和安装

1、下载所需版本`（如https://get.helm.sh/helm-v3.10.0-linux-amd64.tar.gz）`

2、解压它`(tar -zxvf helm-v3.10.0-linux-amd64.tar.gz)`

3、在unpack目录中找到helm二进制文件，并将其移动到所需的目的地`mv linux-amd64/helm /usr/local/bin/helm`



##### Metric server
kube-apiserver 增加以下配置

1、聚合层配置
```
--requestheader-client-ca-file=/etc/kubernetes/ssl/aggregator-ca.pem \
--requestheader-allowed-names=aggregator \
--requestheader-extra-headers-prefix=X-Remote-Extra- \
--requestheader-group-headers=X-Remote-Group \
--requestheader-username-headers=X-Remote-User \
--proxy-client-cert-file=/etc/kubernetes/ssl/aggregator.pem \
--proxy-client-key-file=/etc/kubernetes/ssl/aggregator-key.pem \
--enable-aggregator-routing=true

systemctl restart kube-apiserver
```

2、部署metrics server

```
# 下载 metrics-server-helm-chart-3.11.0
https://github.com/kubernetes-sigs/metrics-server/releases

# 修改chart values.yaml文件
# 将镜像修改为docker.io
image:
  repository: docker.io/bitnami/metrics-server
  tag: "0.6.4"

# 默认参数禁用证书验证
defaultArgs:
  - --cert-dir=/tmp
  - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
  - --kubelet-use-node-status-port
  - --metric-resolution=15s
  - --kubelet-insecure-tls=true


# 增加如下，将其调度到master01上
nodeSelector:
    kubernetes.io/hostname: "master01"

tolerations:
   - effect: "NoSchedule"
     operator: "Exists"
```

3、部署
```
helm upgrade --install metrics-server metrics-server \
  --namespace kube-system
```


##### Nginx ingress

1、下载
```
wget https://github.com/kubernetes/ingress-nginx/releases/download/helm-chart-4.7.2/ingress-nginx-4.7.2.tgz
tar xf ingress-nginx-4.7.2.tgz
```
2、配置
```
# values.yaml

# 配置controller镜像
controller:
    name: controller
    image:
        chroot: false
        registry: registry.cn-hangzhou.aliyuncs.com
        image: google_containers/nginx-ingress-controller

# 配置调度到master01节点上
tolerations: 
    - effect: "NoSchedule"
      operator: "Exists"
nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/hostname: "master01"

# 启用hostPort
hostPort:
    enabled: true
    ports:
        http: 80
        https: 443
    
# patch 指定docker 仓库
patch:
    enabled: true
    image:
        registry: docker.io
        image: dyrnq/kube-webhook-certgen
        ...
```

3、部署
```
helm upgrade --install ingress-nginx ingress-nginx --namespace ingress-nginx
```
4、测试

```
kubectl create ingress test-nginx --class=nginx  --rule="www.mynginx.com/*=nginx-service-nodeport:80"
```
设置hosts 浏览器输入www.mynginx.com测试


##### nfs 控制器




##### jenkins

1、为Jenkins创建命名空间。最好将所有DevOps工具归类为与其他应用程序分开的名称空间。
```
kubectl create namespace devops-tools
```
2、创建`serviceaccount.yaml`,并绑定授权
```
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    app: jenkins
  name: jenkins-admin
rules:
- apiGroups:
  - '*'
  resources:
  - statefulsets
  - services
  - replicationcontrollers
  - replicasets
  - podtemplates
  - podsecuritypolicies
  - pods
  - pods/log
  - pods/exec
  - podpreset
  - poddisruptionbudget
  - persistentvolumes
  - persistentvolumeclaims
  - jobs
  - endpoints
  - deployments
  - deployments/scale
  - daemonsets
  - cronjobs
  - configmaps
  - namespaces
  - events
  - secrets
  verbs:
  - create
  - get
  - watch
  - delete
  - list
  - patch
  - update
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
  - update
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: jenkins-admin
  namespace: devops-tools
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  name: jenkins-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: jenkins-admin
subjects:
- kind: ServiceAccount
  name: jenkins-admin
  namespace: devops-tools
```
3、创建持久化卷`volume.yaml` （nfs、或者本地、或者其他存储）
```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: jenkins-local-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: jenkins-pv-volume
  labels:
    type: local
spec:
  storageClassName: jenkins-local-storage
  capacity:
    storage: 500Gi
  claimRef:   # 预留 只允许如下pvc进行绑定
    name: jenkins-pvc-claim
    namespace: devops-tools
  accessModes:
    - ReadWriteOnce
  local:                      # 本地卷
    path: /home/jenkins/data
  nodeAffinity:                # 节点亲和性指定节点
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node03
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: jenkins-pvc-claim
  namespace: devops-tools
spec:
  storageClassName: jenkins-local-storage
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 500Gi
```

4、创建`deployment.yaml`部署文件。
- `securityContext`用于Jenkins pod能够写入本地持久卷
- 存活和就绪状态探测器用来监测jenkins的健康状况。
- 基于本地存储类的本地持久卷，持久化Jenkins数据路径`/var/jenkins_home`

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jenkins
  namespace: devops-tools
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jenkins-server
  template:
    metadata:
      labels:
        app: jenkins-server
    spec:
      securityContext:
            fsGroup: 1000
            runAsUser: 1000
      serviceAccountName: jenkins-admin
      tolerations:
       - effect: NoSchedule
         operator: Exists 
      containers:
        - name: jenkins
          image: jenkins/jenkins:2.414.1-lts
          resources:
            limits:
              memory: "2Gi"
              cpu: "1000m"
            requests:
              memory: "1000Mi"
              cpu: "1000m"
          env:
           - name: LIMITS_MEMORY
             valueFrom:
               resourceFieldRef:
                 resource: limits.memory
                 divisor: Gi
           - name: JAVA_OPTS  #设置变量，指定时区和 jenkins slave 执行者设置
             value: "-Duser.timezone=Asia/Shanghai"

          ports:
            - name: httpport
              containerPort: 8080
            - name: jnlpport
              containerPort: 50000
          livenessProbe:
            httpGet:
              path: "/login"
              port: 8080
            initialDelaySeconds: 90
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 5
          readinessProbe:
            httpGet:
              path: "/login"
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          volumeMounts:
            - name: jenkins-data
              mountPath: /var/jenkins_home
      volumes:
        - name: jenkins-data
          persistentVolumeClaim:
              claimName: jenkins-pvc-claim
```
5、创建service
```
apiVersion: v1
kind: Service
metadata:
  name: jenkins-service
  namespace: devops-tools
spec:
  type: ClusterIP
  selector:
    app: jenkins-server
  ports:
  - name: web
    port: 8080
    targetPort: httpport

  - name: agent
    port: 50000
    targetPort: jnlpport
```

6、创建ingress
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jenkins
  namespace: devops-tools
spec:
  ingressClassName: nginx
  rules:
  - host: www.myjenkins.com
    http:
      paths:
      - backend:
          service:
            name: jenkins-service
            port:
              number: 8080
        path: /
        pathType: Prefix
```

##### 安装 harbor

官网
- https://github.com/goharbor/harbor-helm


1、下载chart
```
helm repo add harbor https://helm.goharbor.io
helm pull harbor/harbor
tar zxvf harbor-1.13.0.tgz
```
2、修改配置values.yaml

- ingress 配置

```
# ingress 配置
expose:
  type: ingress
  tls:
    enabled: true
    certSource: auto
    auto:
      commonName: ""
    secret:
      secretName: ""
  ingress:
    hosts:
      core: xld.harbor.domain   # host
```

- redis 配置(内部)
```
redis:
  type: internal
  internal:
    serviceAccountName: ""
    automountServiceAccountToken: false
    image:
      repository: goharbor/redis-photon
      tag: v2.9.0
    resources:
      requests:
        memory: 256Mi
        cpu: 100m
    extraEnvVars: []
    nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/hostname: "node03"

```
- db数据库配置
```
database:
  type: internal
  internal:
    serviceAccountName: ""
    automountServiceAccountToken: false
    image:
      repository: goharbor/harbor-db
      tag: v2.9.0
    password: "changeit123654"
    shmSizeLimit: 512Mi
    resources:
      requests:
        memory: 1024Mi
        cpu: 1000m
    nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/hostname: "node03"
```



- registry 配置
```
registry:
  serviceAccountName: ""
  automountServiceAccountToken: false
  registry:
    image:
      repository: goharbor/registry-photon
      tag: v2.9.0
    resources:
      requests:
        memory: 500Mi
        cpu: 500m
    extraEnvVars: []
  controller:
    image:
      repository: goharbor/harbor-registryctl
      tag: v2.9.0
    resources:
      requests:
        memory: 256Mi
        cpu: 200m
    extraEnvVars: []
  replicas: 1
  revisionHistoryLimit: 10
  nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/hostname: "node03"
```

- 禁用trivy
```
trivy:
  enabled: false
```

- 配置portal
```
portal:
  image:
    repository: goharbor/harbor-portal
    tag: v2.9.0
  serviceAccountName: ""
  automountServiceAccountToken: false
  replicas: 1
  revisionHistoryLimit: 10
  resources:
    requests:
      memory: 256Mi
      cpu: 200m
  nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/hostname: "node03"
```
- 配置core
```
core:
  image:
    repository: goharbor/harbor-core
    tag: v2.9.0
  resources:
    requests:
      memory: 256Mi
      cpu: 200m
  nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/hostname: "node03"
```
-  配置jobservice

```
jobservice:
  image:
    repository: goharbor/harbor-jobservice
    tag: v2.9.0
  replicas: 1
  revisionHistoryLimit: 10
  resources:
     requests:
       memory: 256Mi
       cpu: 200m
  nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/hostname: "node03"
```
- 其它配置

```
# 加密密钥(16)
secretKey: "xiaolangdisecure"
# 密码
harborAdminPassword: "H12345xld"
```

- 持久化
```
persistence:
  enabled: true
  resourcePolicy: "keep"
  persistentVolumeClaim:
    registry:
      existingClaim: ""
      storageClass: "harbor-local-storage"
      subPath: ""
      accessMode: ReadWriteOnce
      size: 200Gi
      annotations: {}
    jobservice:
      jobLog:
        existingClaim: ""
        storageClass: "harbor-local-storage"
        subPath: ""
        accessMode: ReadWriteOnce
        size: 10Gi
        annotations: {}
    database:
      existingClaim: ""
      storageClass: "harbor-local-storage"
      subPath: ""
      accessMode: ReadWriteOnce
      size: 10Gi
      annotations: {}
    redis:
      existingClaim: ""
      storageClass: "harbor-local-storage"
      subPath: ""
      accessMode: ReadWriteOnce
      size: 1Gi
      annotations: {}
```

- 创建local类型pv
```
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: harbor-db-pv
  labels:
    type: local
spec:
  storageClassName: harbor-local-storage 
  capacity:
    storage: 20Gi
  claimRef:   
    name: database-data-harbor-database-0
    namespace: devops-tools
  accessModes:
    - ReadWriteOnce
  local:                      # 本地卷
    path: /data/harbor/db
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node03

---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: harbor-redis-pv
  labels:
    type: local
spec:
  storageClassName: harbor-local-storage 
  capacity:
    storage: 10Gi
  claimRef:   
    name: data-harbor-redis-0
    namespace: devops-tools
  accessModes:
    - ReadWriteOnce
  local:                      # 本地卷
    path: /data/harbor/redis
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node03
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: harbor-registry-pv
  labels:
    type: local
spec:
  storageClassName: harbor-local-storage 
  capacity:
    storage: 200Gi
  claimRef:   
    name: harbor-registry
    namespace: devops-tools
  accessModes:
    - ReadWriteOnce
  local:                      # 本地卷
    path: /data/harbor/registry
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node03
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: harbor-jobservice-pv
  labels:
    type: local
spec:
  storageClassName: harbor-local-storage 
  capacity:
    storage: 20Gi
  claimRef:   
    name: harbor-jobservice
    namespace: devops-tools
  accessModes:
    - ReadWriteOnce
  local:                      # 本地卷
    path: /data/harbor/job
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node03

```

- TLS证书自动创建`tls.key  tls.crt`
- 通过ingress公开Harbor服务 
- 指定nginx 控制器`kubectl patch ingress harbor-ingress -n devops-tools  -p '{"spec":{"ingressClassName":"nginx"}}'`