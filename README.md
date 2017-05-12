# non-masquerade-daemon

The non-masquerade-daemon configures `iptables` rules to `MASQUERADE` traffic outside link-local (optional, enabled by default) and additional arbitrary IP ranges.

It creates an `iptables` chain called `NON-MASQUERADE-DAEMON`, which contains match rules for link local (`169.254.0.0/16`) and each of the user-specified IP ranges. It also creates a rule in `POSTROUTING` that jumps to this chain for any traffic not bound for a `LOCAL` destination.

IPs that match the rules (except for the final rule) in `NON-MASQUERADE-DAEMON` are *not* subject to `MASQUERADE` via the `NON-MASQUERADE-DAEMON` chain (they `RETURN` early from the chain). The final rule in the `NON-MASQUERADE-DAEMON` chain will `MASQUERADE` any non-`LOCAL` traffic.

`RETURN` in `NON-MASQUERADE-DAEMON` resumes rule processing at the next rule the calling chain, `POSTROUTING`. Take care to avoid creating additional rules in `POSTROUTING` that cause packets bound for your configured ranges to undergo `MASQUERADE`.

## Launching the daemon
This repo includes an example yaml file that can be used to launch the non-masquerade-daemon as a DaemonSet in a Kubernetes cluster.

```
kubectl create -f non-masquerade-daemon.yaml
```

The spec in `non-masquerade-daemon.yaml` specifies the `kube-system` namespace for the daemon pods.

## Configuring the daemon

Important: You should not attempt to run this daemon in a cluster where the Kubelet is also configuring a non-masquerade CIDR. You can pass `--non-masquerade-cidr=0.0.0.0/0` to the Kubelet to nullify its rule, which will prevent the Kubelet from interfering with this daemon.

By default, the daemon is configured to treat the three private IP ranges specified by [RFC 1918](https://tools.ietf.org/html/rfc1918) as non-masquerade CIDRs. These ranges are `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. The daemon will also treat link-local (`169.254.0.0/16`) as a non-masquerade CIDR by default.

By default, the daemon is configured to reload its configuration from the `/etc/config/non-masquerade-daemon` file in its container every 60 seconds.

The daemon configuration file should be written in yaml or json syntax, and may contain three optional keys:
- `nonMasqueradeCIDRs []string`: A list strings in CIDR notation that specify the non-masquerade ranges.
- `linkLocal bool`: Whether to use `169.254.0.0/16` as a non-masquerade CIDR. True by default.
- `resyncInterval string`: The interval at which the daemon attempts to reload config from disk. The syntax is any format accepted by Go's [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) function.

The daemon will look for a config file in its container at `/etc/config/non-masquerade-daemon`. This file can be provided via a `ConfigMap`, plumbed into the container via a `ConfigMapVolumeSource`. As a result, the daemon can be reconfigured in a live cluster by creating or editing this `ConfigMap`.

This repo includes a directory-representation of a `ConfigMap` that can configure the daemon (the `daemon-config` directory). To use this directory to create the `ConfigMap` in your cluster:

```
kubectl create configmap non-masquerade-daemon --from-file=daemon-config --namespace=kube-system
```

Note that we created the `ConfigMap` in the same namespace as the daemon pods, and named the `ConfigMap` to match the spec in `non-masquerade-daemon.yaml`. This is necessary for the `ConfigMap` to appear in the daemon pods' filesystems.

## Rationale
(from the [incubator proposal](https://gist.github.com/mtaufen/253309166e7d5aa9e9b560600a438447))

This daemon solves the problem of configuring the CIDR ranges for non-masquerade in a cluster (via iptables rules). Today, this is accomplished by passing a `--non-masquerade-cidr` flag to the Kubelet, which only allows one CIDR to be configured as non-masquerade. [RFC 1918](https://tools.ietf.org/html/rfc1918), however, defines three ranges (`10/8`, `172.16/12`, `192.168/16`) for the private IP address space.

Some users will want to communicate between these ranges without masquerade - for instance, if an organization's existing network uses the `10/8` range, they may wish to run their cluster and `Pod`s in `192.168/16` to avoid IP conflicts. They will also want these `Pod`s to be able to communicate efficiently (no masquerade) with each-other *and* with their existing network resources in `10/8`. This requires that every node in their cluster skips masquerade for both ranges.

We are trying to eliminate networking code from the Kubelet, so rather than extend the Kubelet to accept multiple CIDRs, [mtaufen/non-masquerade-daemon](https://github.com/mtaufen/non-masquerade-daemon) allows you to run a DaemonSet that configures a list of CIDRs as non-masquerade.

## Incubator

This is a [Kubernetes Incubator project](https://github.com/kubernetes/community/blob/master/incubator.md). The incubator team for the project is:

- Author: Mike Taufen (@mtaufen)
- Sponsor: Tim Hockin (@thockin)
- Champion: Bowei Du (@bowei)
- SIG: sig-awesome

## Releasing

See [RELEASE](RELEASE.md).

## Developing

Clone the repo to `$GOPATH/src/k8s.io/non-masquerade-daemon`.

The build tooling is based on [thockin/go-build-template](https://github.com/thockin/go-build-template).

Run `make` or `make build` to compile the non-masquerade-daemon.  This will use a Docker image
to build the daemon, with the current directory volume-mounted into place.  This
will store incremental state for the fastest possible build.  Run `make
all-build` to build for all architectures.

Run `make test` to run the unit tests.

Run `make container` to build the container image.  It will calculate the image
tag based on the most recent git tag, and whether the repo is "dirty" since
that tag (see `make version`).  Run `make all-container` to build containers
for all architectures.

Run `make push` to push the container image to `REGISTRY`.  Run `make all-push`
to push the container images for all architectures.

Run `make clean` to clean up.
