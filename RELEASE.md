# Release Process

The daemon is released on an as-needed basis. The process is as follows:

1. Someone must file an issue proposing a new release with a changelog since the last release.
1. All [OWNERS](OWNERS) must LGTM this release.
1. An OWNER (who must have push access to the `google_containers` project):
    1. Tags the commit approved for release with `git tag -s vx.x.x`. The `vx.x.x` is semver with a leading `v`.
    1. Runs `make push`, to build and push the container image for the release to `google_containers`.
    1. Pushes the tag with `git push vx.x.x`. 
1. The release issue is closed.
1. An announcement email is sent to `kubernetes-dev@googlegroups.com` with the subject `[ANNOUNCE] non-masquerade-daemon vx.x.x is released`.