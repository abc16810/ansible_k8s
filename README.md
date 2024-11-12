
## Requirements

运行Ansible的主机需要以下Python依赖项:

- `python >= 3.6.0` - [参见下面的注释](#important-note-about-python).
- `ansible >= 2.9.16` or `ansible-base >= 2.14.0`

你可以使用这个存储库中的requirements.txt文件来安装依赖: `pip3 install -r requirements.txt`。

此角色已针对以下Linux发行版进行了测试:

- Alpine Linux
- Amazon Linux 2
- Archlinux
- CentOS 8
- Debian 11
- Fedora 31
- Fedora 32
- Fedora 33
- openSUSE Leap 15
- RockyLinux 8
- Ubuntu 20.04 LTS

:warning: 该角色v1版本只支持 `k8s >= v1.25.0`

### Global/Cluster Variables

| 变量 | 描述 | 默认值 |
|----|----|----|
| `k8s_state`  | k8s状态: installed, started, stopped, downloaded, uninstalled, validated.  | installed  |
| `k8s_release_version`  | 指定k8s安装版本, eg. `v1.25.0`.  为stable指定`false` | `false`     |

### Ansible 控制配置变量

下面的变量用来改变Ansible中角色的执行方式:
特别是在特权升级方面。

| 变量                   | 描述                                                            | 默认值 |
|------------------------|----------------------------------------------------------------|---------------|
| `k8s_skip_validation`  | 跳过所有验证配置的任务                  | `false`       |
| `k8s_skip_env_checks`  | 跳过所有检查环境配置的任务           | `false`       |
| `k8s_skip_post_checks` | 跳过所有检查执行后状态的任务                | `false`       |
| `k8s_become`           | 升级需要root权限的任务的用户权限. | `true`       |



```
# 生成资产 
declare -a IPS=(10.10.1.3 10.10.1.4 10.10.1.5)
CONFIG_FILE=inventory/mycluster/hosts.yaml python3 contrib/inventory_builder/inventory.py ${IPS[@]}
# 然后使用inventory/mycluster/hosts.yaml 作为资产文件， 按照需求进行调整
all:
  hosts:
    node1:
      ansible_host: 192.168.119.38
      ip: 192.168.119.38
      access_ip: 192.168.119.38
    node2:
      ansible_host: 192.168.119.73
      ip: 192.168.119.73
      access_ip: 192.168.119.73
    node3:
      ansible_host: 192.168.119.217
      ip: 192.168.119.217
      access_ip: 192.168.119.217
    node4:
      ansible_host: 192.168.119.240
      ip: 192.168.119.240
      access_ip: 192.168.119.240
  children:
    kube_control_plane:
      hosts:
        node1:
    kube_node:
      hosts:
        node1:
        node2:
        node3:
        node4:
    etcd:
      hosts:
        node1:
        node2:
        node3:
    k8s_cluster:
      children:
        kube_control_plane:
        kube_node:
    calico_rr:
      hosts: {}

```


#### pre_setup
- 禁用swap
- 


#### etcd

将`cert_management`设置为script，ansible 将自动生成etcd证书


生成etds证书
1、创建目录`/etc/ssl/etcd/ssl`
2、在etcd第一个主机上创建存放证书脚本目录`/usr/local/bin/etcd-scripts`
3、在etcd第一个主机上生成openssl模块文件`/etc/ssl/etcd/openssl.conf`
  ```
  [req]
  req_extensions = v3_req
  distinguished_name = req_distinguished_name

  [req_distinguished_name]

  [ v3_req ]
  basicConstraints = CA:FALSE
  keyUsage = nonRepudiation, digitalSignature, keyEncipherment
  subjectAltName = @alt_names

  [ ssl_client ]
  extendedKeyUsage = clientAuth, serverAuth
  basicConstraints = CA:FALSE
  subjectKeyIdentifier=hash
  authorityKeyIdentifier=keyid,issuer
  subjectAltName = @alt_names

  [ v3_ca ]
  basicConstraints = CA:TRUE
  keyUsage = nonRepudiation, digitalSignature, keyEncipherment
  subjectAltName = @alt_names
  authorityKeyIdentifier=keyid:always,issuer

  [alt_names]
  DNS.1 = localhost
  DNS.2 = master01        # etcd节点group name
  DNS.3 = master02
  DNS.4 = node01
  DNS.5 = etcd.kube-system.svc.cluster.local
  DNS.6 = etcd.kube-system.svc
  DNS.7 = etcd.kube-system
  DNS.8 = etcd
  IP.1 = 10.4.56.124            # etcd节点IP （fallback_ips）
  IP.2 = 10.4.56.230
  IP.3 = 10.4.56.115
  IP.4 = 127.0.0.1
  ```
4、在etcd第一个主机上生成证书脚本文件`/usr/local/bin/etcd-scripts/make-ssl-etcd.sh`
5、在etcd第一个主机上运行脚本
  ```
  # 运行etcd和kube控制平面节点的cert生成脚本
  # MASTERS 变量生成etcd节点上的gen_master_certs为true的证书
  # 包括成员证书和admin证书
  bash -x /usr/local/bin/etcd-scripts/make-ssl-etcd.sh -f /etc/ssl/etcd/openssl.conf -d /etc/ssl/etcd/ssl
  # HOSTS 变量生成kube_control_plane节点上gen_node_certs为true的证书
  # 包括 节点证书
  ```
  6、将证书拷贝到其它etcd节点
  7、将证书拷贝到和etcd不通节点的控制节点上
  8、设置证书权限700
  9、在etcd节点和控制节点信任Etcd CA根证书（可忽略）
  10、安装etcd`(/usr/local/bin/etcd)`
  11、配置etcd`(/etc/etcd.env)`
  ```
  # Environment file for etcd v3.5.7
  ETCD_DATA_DIR=/var/lib/etcd
  ETCD_ADVERTISE_CLIENT_URLS=https://10.4.56.116:2379
  ETCD_INITIAL_ADVERTISE_PEER_URLS=https://10.4.56.116:2380
  ETCD_INITIAL_CLUSTER_STATE=new
  ETCD_METRICS=basic
  ETCD_LISTEN_CLIENT_URLS=https://10.4.56.116:2379,https://127.0.0.1:2379
  ETCD_ELECTION_TIMEOUT=5000
  ETCD_HEARTBEAT_INTERVAL=250
  ETCD_INITIAL_CLUSTER_TOKEN=k8s_etcd
  ETCD_LISTEN_PEER_URLS=https://10.4.56.116:2380
  ETCD_NAME=node02
  ETCD_PROXY=off
  ETCD_INITIAL_CLUSTER=node02=https://10.4.56.116:2380,node03=https://10.4.56.106:2380
  ETCD_AUTO_COMPACTION_RETENTION=8
  # Flannel need etcd v2 API
  ETCD_ENABLE_V2=true

  # TLS settings
  ETCD_TRUSTED_CA_FILE=/etc/ssl/etcd/ssl/ca.pem
  ETCD_CERT_FILE=/etc/ssl/etcd/ssl/member-node02.pem
  ETCD_KEY_FILE=/etc/ssl/etcd/ssl/member-node02-key.pem
  ETCD_CLIENT_CERT_AUTH=true

  ETCD_PEER_TRUSTED_CA_FILE=/etc/ssl/etcd/ssl/ca.pem
  ETCD_PEER_CERT_FILE=/etc/ssl/etcd/ssl/member-node02.pem
  ETCD_PEER_KEY_FILE=/etc/ssl/etcd/ssl/member-node02-key.pem
  ETCD_PEER_CLIENT_CERT_AUTH=True



  # CLI settings
  ETCDCTL_ENDPOINTS=https://127.0.0.1:2379
  ETCDCTL_CACERT=/etc/ssl/etcd/ssl/ca.pem
  ETCDCTL_KEY=/etc/ssl/etcd/ssl/admin-node02-key.pem
  ETCDCTL_CERT=/etc/ssl/etcd/ssl/admin-node02.pem

  # ETCD 3.5.x issue
  # https://groups.google.com/a/kubernetes.io/g/dev/c/B7gJs88XtQc/m/rSgNOzV2BwAJ?utm_medium=email&utm_source=footer
  ETCD_EXPERIMENTAL_INITIAL_CORRUPT_CHECK=True

  ```

12、设置启动文件`etcd.service`
  ```
  [root@node02 ssl]# cat /etc/systemd/system/etcd.service 
  [Unit]
  Description=etcd
  
  After=network.target

  [Service]
  Type=notify
  User=root
  EnvironmentFile=/etc/etcd.env
  ExecStart=/usr/local/bin/etcd
  NotifyAccess=all
  Restart=always
  RestartSec=10s
  LimitNOFILE=40000

  [Install]
  WantedBy=multi-user.target
  ```

13、开机自启动、健康检测



#### kube control plane


