+++
tags = ["docker", "containers", "devops", "troubleshooting", "debugging", "containerization", "sre"]
draft = false
title = "Docker Troubleshooting Guide: Comprehensive Solutions for Common Container Issues (2025)"
description = "In-depth guide for troubleshooting Docker issues including container crashes, networking problems, and performance bottlenecks. Features practical commands, debugging techniques, and expert solutions for DevOps engineers and SREs."
keywords = "Docker troubleshooting, container debugging, Docker networking issues, Docker performance optimization, container logs, Docker compose issues, container communication, Docker best practices, DevOps troubleshooting, container monitoring"
author = "bloodstiller"
date = 2025-03-10
toc = true
bold = true
next = true
+++

This is a checklist for troubleshooting Docker issues. It is not a comprehensive guide, it is mainly for my own reference but is useful for other.


## Docker Troubleshooting Checklist {#docker-troubleshooting-checklist}


### Container Issues {#container-issues}


#### Container Restarting Loop {#container-restarting-loop}

<!--list-separator-->

-  Check container status and logs

    -   Check status: `docker ps -a`
    -   View logs: `docker logs <container_id>`
    -   Follow logs: `docker logs -f <container_id>`
    -   Last N lines: `docker logs --tail=100 <container_id>`

<!--list-separator-->

-  Common causes and solutions

    -   [ ] Check if entrypoint/CMD is correct
    -   [ ] Verify environment variables are set properly
    -   [ ] Check for application crashes in logs
    -   [ ] Verify container has enough resources
        -   Memory: `docker stats`
        -   Disk space: `df -h`


#### Container Won't Start {#container-won-t-start}

<!--list-separator-->

-  Basic checks

    -   [ ] Verify image exists: `docker images`
    -   [ ] Check port conflicts: `docker ps`
    -   [ ] Check local port usage: `netstat -antp | grep -i list`
    -   [ ] Inspect container: `docker inspect <container_id>`
    -   [ ] Check container configuration
        -   Volume mounts
            -   Verify host paths exist: `ls -la <host_path>`
            -   Check permissions: `ls -la <host_path> | grep $(whoami)`
            -   Inspect volume mounts: `docker inspect <container_id> | grep -A 10 Mounts`
            -   List volumes: `docker volume ls`
        -   Port mappings
            -   Check container port mappings: `docker port <container_id>`
            -   Verify host port availability: `ss -tulpn`
            -   Review docker-compose ports section
            -   Check for port conflicts in other containers
        -   Network settings
            -   List container networks: `docker network ls`
            -   Check container network mode: `docker inspect <container_id> | grep -i network`
            -   Verify DNS resolution: `docker exec <container_id> cat /etc/resolv.conf`
            -   Check network driver: `docker network inspect <network_name> | grep -i driver`
            -   Test internal connectivity: `docker exec <container_id> ping <other_container>`


### Build Issues {#build-issues}


#### Image Build Failures {#image-build-failures}

<!--list-separator-->

-  Common checks

    -   [ ] Verify Dockerfile syntax
    -   [ ] Check build context
    -   [ ] Run with verbose output: `docker build --progress=plain .`
    -   [ ] Clear build cache: `docker builder prune`

<!--list-separator-->

-  Network-related

    -   [ ] Check network connectivity
    -   [ ] Verify proxy settings if applicable
    -   [ ] Test registry access


### Network Issues {#network-issues}


#### Connectivity Problems {#connectivity-problems}

<!--list-separator-->

-  Basic diagnostics

    -   [ ] List networks: `docker network ls`
    -   [ ] Inspect network: `docker network inspect <network_name>`
    -   [ ] Check DNS resolution inside container: `docker exec <container_id> ping <hostname>`


#### Port Mapping Issues {#port-mapping-issues}

<!--list-separator-->

-  Verification steps

    -   [ ] Check port bindings: `docker port <container_id>`
    -   [ ] Verify host ports are available: `netstat -tulpn`
    -   [ ] Test connectivity: `curl localhost:<port>`


### Resource Issues {#resource-issues}


#### Memory Problems {#memory-problems}

<!--list-separator-->

-  Monitoring and diagnostics

    -   [ ] Check memory usage: `docker stats`
    -   [ ] Review container limits: `docker inspect <container_id> | grep -i memory`
    -   [ ] Check system memory: `free -h`


#### Disk Space Issues {#disk-space-issues}

<!--list-separator-->

-  Cleanup steps

    -   [ ] Remove unused containers: `docker container prune`
    -   [ ] Remove unused images: `docker image prune`
    -   [ ] Remove unused volumes: `docker volume prune`
    -   [ ] Remove all unused resources: `docker system prune`
    -   [ ] Check disk usage: `docker system df`


### Logging and Debugging {#logging-and-debugging}


#### Advanced Logging {#advanced-logging}

<!--list-separator-->

-  Commands

    -   [ ] View daemon logs: `journalctl -u docker.service`
    -   [ ] Enable debug mode: `dockerd -D`
    -   [ ] Check container events: `docker events`


#### Container Debugging {#container-debugging}

<!--list-separator-->

-  Interactive debugging

    -   [ ] Enter running container: `docker exec -it <container_id/name> /bin/sh`
    -   [ ] Inspect processes: `docker top <container_id>`
    -   [ ] View container details: `docker inspect <container_id>`


### Compose Issues {#compose-issues}


#### Docker Compose Troubleshooting {#docker-compose-troubleshooting}

<!--list-separator-->

-  Common checks

    -   [ ] Validate compose file: `docker-compose config`
    -   [ ] Check service dependencies: `docker-compose ps`
    -   [ ] Force recreation: `docker-compose up --force-recreate`
    -   [ ] Check compose logs: `docker-compose logs -f <service_name>`
    -   [ ] Verify environment file: `cat .env`


### Permission Issues {#permission-issues}


#### Common Permission Problems {#common-permission-problems}

<!--list-separator-->

-  File system permissions

    -   [ ] Check Docker socket permissions: `ls -la /var/run/docker.sock`
    -   [ ] Verify user is in docker group: `groups ${USER}`
    -   [ ] Fix ownership issues: `chown -R <user>:<group> <path>`
    -   [ ] SELinux contexts: `ls -lZ`


### Storage Driver Issues {#storage-driver-issues}


#### Troubleshooting Steps {#troubleshooting-steps}

<!--list-separator-->

-  Driver checks

    -   [ ] Check current storage driver: `docker info | grep "Storage Driver"`
    -   [ ] Verify supported drivers: `docker info | grep -A 8 "Storage Driver"`
    -   [ ] Monitor storage driver errors: `journalctl -fu docker.service | grep storage`


### Registry Issues {#registry-issues}


#### Authentication and Access {#authentication-and-access}

<!--list-separator-->

-  Common problems

    -   [ ] Test registry login: `docker login <registry-url>`
    -   [ ] Check credentials file: `cat ~/.docker/config.json`
    -   [ ] Verify registry certificates
    -   [ ] Test registry connectivity: `curl -v https://<registry-url>/v2/`


### Container Health Checks {#container-health-checks}


#### Health Monitoring {#health-monitoring}

<!--list-separator-->

-  Health status

    -   [ ] View health status: `docker inspect --format='{{.State.Health.Status}}' <container_id>`
    -   [ ] Check health check config: `docker inspect --format='{{.Config.Healthcheck}}' <container_id>`
    -   [ ] Monitor health check logs: `docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' <container_id>`


### Performance Issues {#performance-issues}


#### Container Performance {#container-performance}

<!--list-separator-->

-  Monitoring tools

    -   [ ] Check CPU usage: `docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"`
    -   [ ] Monitor I/O operations: `docker stats --format "table {{.Container}}\t{{.BlockIO}}"`
    -   [ ] Check process list: `docker top <container_id> aux`
    -   [ ] Resource constraints: `docker inspect <container_id> | grep -i -A 10 "hostconfig"`


### Networking Deep Dive {#networking-deep-dive}


#### Advanced Network Troubleshooting {#advanced-network-troubleshooting}

<!--list-separator-->

-  Debug tools

    -   [ ] Check iptables rules: `iptables -L -n`
    -   [ ] Inspect bridge network: `ip addr show docker0`
    -   [ ] Track network packets: `tcpdump -i docker0`
    -   [ ] Check network namespaces: `ip netns list`


### Common Gotchas {#common-gotchas}


#### Known Issues {#known-issues}

<!--list-separator-->

-  Time and Timezone Issues

    -   [ ] Time synchronization between host and containers
        -   Check host time: `date`
        -   Check container time: `docker exec <container_id> date`
        -   Verify timezone file mount: `docker inspect <container_id> | grep /usr/share/zoneinfo`
        -   Add timezone environment: `-e TZ=UTC`

<!--list-separator-->

-  File System Issues

    -   [ ] Case sensitivity in volume mounts
        -   Linux is case-sensitive, Windows/Mac aren't
        -   Check actual file names: `ls -la`
        -   Verify mount points: `docker inspect <container_id> | grep -A 10 Mounts`
        -   Test file access: `docker exec <container_id> ls -la /path/to/mount`

<!--list-separator-->

-  Encoding and Locale Issues

    -   [ ] UTF-8 and character encoding
        -   Check container locale: `docker exec <container_id> locale`
        -   Verify file encoding: `file -i <filename>`
        -   Set container locale: `-e LANG=C.UTF-8`
        -   Check log file encoding: `less <logfile>` (look for strange characters)

<!--list-separator-->

-  Process Management

    -   [ ] Zombie process handling
        -   Check for zombies: `docker top <container_id> | grep -i defunct`
        -   Verify init process: `docker inspect <container_id> | grep -i pid`
        -   Use init system: `--init` flag when running container
        -   Monitor process states: `docker exec <container_id> ps aux`

<!--list-separator-->

-  Daemon Management

    -   [ ] Docker daemon configuration
        -   Check auto-start: `systemctl is-enabled docker`
        -   Verify daemon config: `cat /etc/docker/daemon.json`
        -   Monitor daemon status: `systemctl status docker`
        -   Check startup options: `ps aux | grep dockerd`


### Container Communication {#container-communication}


#### Inter-Container Networking {#inter-container-networking}

<!--list-separator-->

-  Basic Connectivity

    -   [ ] Check if containers are on same network
        -   List networks: `docker network ls`
        -   Inspect network: `docker network inspect <network_name>`
        -   List connected containers: `docker network inspect <network_name> | grep -A 5 "Containers"`

<!--list-separator-->

-  DNS Resolution

    -   [ ] Verify DNS resolution between containers
        -   Test DNS lookup: `docker exec <container_id> nslookup <other_container_name>`
        -   Check DNS settings: `docker exec <container_id> cat /etc/resolv.conf`
        -   Verify /etc/hosts: `docker exec <container_id> cat /etc/hosts`
        -   Test DNS server: `docker exec <container_id> dig <other_container_name>`

<!--list-separator-->

-  Network Debugging

    -   [ ] Troubleshoot connectivity issues
        -   Ping test: `docker exec <container_id> ping <other_container_name>`
        -   TCP connection test: `docker exec <container_id> nc -vz <other_container_name> <port>`
        -   Trace route: `docker exec <container_id> traceroute <other_container_name>`
        -   Check network isolation: `docker network inspect <network_name> | grep -i "internal"`

<!--list-separator-->

-  Common Network Issues

    -   [ ] Check for common problems
        -   Verify container names match DNS entries
        -   Ensure ports are exposed between containers
        -   Check network driver compatibility
        -   Verify no IP conflicts: `docker network inspect <network_name> | grep -i "ipv4"`

<!--list-separator-->

-  Advanced Network Diagnostics

    -   [ ] Deep dive network troubleshooting
        -   Capture network traffic: `docker exec <container_id> tcpdump -i eth0`
        -   Check iptables rules: `iptables -L -n -v | grep <container_ip>`
        -   Verify network policies: `docker network inspect <network_name> | grep -i "policy"`
        -   Monitor network metrics: `docker stats --format "table {{.Container}}\t{{.NetIO}}"`

<!--list-separator-->

-  Docker Compose Networking

    -   [ ] Compose-specific network issues
        -   Check service dependencies: `docker-compose ps`
        -   Verify network definitions in compose file
        -   Test service discovery: `docker-compose exec <service_name> ping <other_service>`
        -   Check network aliases: `docker-compose exec <service_name> nslookup <service_alias>`


### Emergency Recovery {#emergency-recovery}


#### Recovery Steps {#recovery-steps}

<!--list-separator-->

-  When everything fails

    -   [ ] Backup container data: `docker cp <container_id>:/path/to/data ./backup`
    -   [ ] Save container state: `docker commit <container_id> backup-image`
    -   [ ] Export container filesystem: `docker export <container_id> > container.tar`
    -   [ ] Restart Docker daemon: `systemctl restart docker`
    -   [ ] Check Docker daemon status: `systemctl status docker`


### Environment Specific {#environment-specific}


#### Different OS Considerations {#different-os-considerations}

<!--list-separator-->

-  Platform specific

    -   [ ] Windows path formats in volume mounts
    -   [ ] MacOS file sharing settings
    -   [ ] Linux cgroup configuration
    -   [ ] Container user mapping issues
