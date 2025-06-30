# Notice for Docker image

A Tractus-X IssuerService using memory-based storage, and an in-memory vault as secret store.

_Please not that this distribution is only intended for testing and demo purposes!_

DockerHub: <https://hub.docker.com/r/tractusx/issuerservice>

Eclipse Tractus-X product(s) installed within the image:

## Tractus-X IssuerService

- GitHub: <https://github.com/eclipse-tractusx/tractusx-issuerservice>
- Project home: <https://projects.eclipse.org/projects/automotive.tractusx>
- Dockerfile: <https://github.com/eclipse-tractusx/tractusx-issuerservice/blob/main/runtimes/issuerservice-memory/src/main/docker/Dockerfile>
- Project license: [Apache License, Version 2.0](https://github.com/eclipse-tractusx/tractusx-edc/blob/main/LICENSE)

## Used base image

- [eclipse-temurin:23_37-jre-alpine](https://github.com/adoptium/containers)
- Official Eclipse Temurin DockerHub page: <https://hub.docker.com/_/eclipse-temurin>
- Eclipse Temurin Project: <https://projects.eclipse.org/projects/adoptium.temurin>
- Additional information about the Eclipse Temurin
  images: <https://github.com/docker-library/repo-info/tree/master/repos/eclipse-temurin>

As with all Docker images, these likely also contain other software which may be under other licenses (such as Bash, etc
from the base distribution, along with any direct or indirect dependencies of the primary software being contained).

As for any pre-built image usage, it is the image user's responsibility to ensure that any use of this image complies
with any relevant licenses for all software contained within.
