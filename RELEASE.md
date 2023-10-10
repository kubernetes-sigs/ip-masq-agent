# Release Process

The ip-masq-agent is released on an as-needed basis. The process is as follows:

1. Someone must file an issue proposing a new release with a changelog since the last release.
1. All [OWNERS](OWNERS) must LGTM this release.
1. An OWNER (who must have push access to the `k8s-staging-networking` project):
    1. Tags the commit approved for release with `git tag -s vx.x.x`. The `vx.x.x` is semver with a leading `v`.
    1. Runs `make push`, to build and push the container image for the release to `k8s-staging-networking`.
    1. Pushes the tag with `git push vx.x.x`. 
1. The release issue is closed.
1. An announcement email is sent to `kubernetes-dev@googlegroups.com` with the subject `[ANNOUNCE] ip-masq-agent vx.x.x is released`.
1. Propose a PR to k8s.io/k8s.gcr.io/images/k8s-staging-networking/images.yaml to add the new image to be promoted.
1. Look for the final image to be available at registry.k8s.io/networking/ip-masq-agent-*

Example:

```
$ git tag
v0.2.0
v0.2.1
v0.3.1
v0.4.0
v1.0.0
v2.0.0

# Pick the next release number

$ git tag -am "v2.0.1" v2.0.1

$ make manifest-list
<...lots of output...>
Digest: sha256:504833aedf3f14379e73296240ed44d54aecd4c02367b004452dfeca2465e5bf 1556

<Merge a PR that adds a line of the form
  "sha256:504833aedf3f14379e73296240ed44d54aecd4c02367b004452dfeca2465e5bf": ["v2.0.1"]
to k8s.io/k8s.gcr.io/images/k8s-staging-networking/images.yaml in the github repository at
https://github.com/kubernetes/k8s.io>
```
