# CVE-2022-0492-Checker
A script to check if a container environment is vulnerable to **container escapes** via _CVE-2022-0492_
<p align="center">
  <img width="200" height="200" src="https://cdn-icons-png.flaticon.com/512/25/25719.png"/>
</p>


# About the vulnerability


On **Feb. 4**, _Linux_ announced **CVE-2022-0492**, a new privilege escalation vulnerability in the kernel. 

**CVE-2022-0492** marks a logical bug in control groups (cgroups), a Linux feature that is a fundamental building block of containers. The issue stands out as one of the simplest Linux privilege escalations discovered in recent times: The Linux kernel mistakenly exposed a privileged operation to unprivileged users.

Fortunately, the default security hardenings in most container environments are enough to prevent container escape. Containers running with AppArmor or SELinux are protected. That being said, if you run containers without best practice hardenings, or with additional privileges, you may be at risk. The "Am I Affected?" section lists vulnerable container configurations and provides instructions on how to test whether a container environment is vulnerable.

Aside from containers, the vulnerability can also allow root host processes with no capabilities, or non-root host processes with the **CAP_DAC_OVERRIDE** capability, to escalate privileges and attain all capabilities. This may allow attackers to circumvent a hardening measure used by certain services, which drop capabilities in an attempt to limit impact if a compromise occurs.

CVE-2022-0492 is now the third kernel vulnerability in recent months that allows malicious containers to escape. In all three vulnerabilities, securing containers with Seccomp and either AppArmor or SELinux was enough to prevent container escape.

# Links : 

- [NVD - CVE-2022-0492 Details](https://nvd.nist.gov/vuln/detail/CVE-2022-0492)
- [Red Hat Bugzilla – **Bug 2051505** - CVE-2022-0492 kernel: cgroups v1 release_agent feature may allow privilege escalation](https://bugzilla.redhat.com/show_bug.cgi?id=2051505)
- [Linux Kernel - **cgroup-v1**: Require capabilities to set release_agent](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183aa120d07c03d9289519c2fe02af)


# Escape methods :

## 1 - User namespace Escape

Mounting a **cgroupfs** requires the **CAP_SYS_ADMIN** capability in the user namespace hosting the current cgroup namespace. By default, containers run without **CAP_SYS_ADMIM**, and thus cannot mount **cgroupfs** in the initial user namespace. But through the **unshare()** syscall, containers can create new user and cgroup namespaces where they possess the CAP_SYS_ADMIN capability and can mount a cgroupfs.

![X](https://i.postimg.cc/0NfTJmPs/image.png)

> **Fig. 1** - A container creating a new user namespace where it'll have the CAP_SYS_ADMIN capability.

Not every container can create a new user namespace – the underlying host must have unprivileged user namespaces enabled. This is the default on recent Ubuntu releases, for example. Since Seccomp blocks the **unshare()** syscall, only containers running without Seccomp can create a new user namespace. The container shown in the attached screenshot runs without Seccomp, **AppArmor or SELinux**.

![Y](https://i.postimg.cc/9QXKH0yg/image.png)

> **Fig. 2** - The container mounts the memory cgroup in the new user and cgroup namespaces.

In the screenshot above, the container successfully mounted a memory cgroup, but you may notice that the **release_agent** file isn't included in the mounted directory!

As mentioned earlier, the **release_agent** file is only visible in the root cgroup. One caveat of mounting a cgroupfs in a cgroup namespace is that you mount the cgroup you belong to, not the root cgroup.

![Z](https://i.postimg.cc/XvqvqV6Q/image.png)

> **Fig. 3** - The container mounting the root RDMA cgroup in the new user and cgroup namespaces.

To exploit the issue, we need to write a malicious release agent to the **release_agent** file. As seen in **Fig. 3** above, that file is owned by root, so only root container processes may set the release agent. **Fig. 4** shows the container setting the release agent, while **Fig. 5** shows a non-root container failing to do so.

![A](https://i.postimg.cc/Rh5w5gb1/image.png)

> **Fig. 4** - A root container setting the release agent.

![A](https://i.postimg.cc/s2CzWS86/image.png)

> **Fig. 5** - Non-root container cannot set the release agent.


The final step of the escape is to invoke the configured **release_agent**, which doesn't require any privileges. Since this step is always doable, it has no implications on whether an environment is vulnerable to **CVE-2022-0492**, and so we decided to leave it out. You can still see how a full exploit looks in the screenshot below.

![Exploited](https://i.postimg.cc/W34Hq12Y/image.png)
> **Fig. 6** - Exploiting **CVE-2022-0492** for container escape, via user namespaces..

## 2 - CAP_SYS_ADMIN Escape

Rather than creating new user and cgroup namespaces, a simpler exploit is possible if the container is granted the **CAP_SYS_ADMIN** capability. A container running with the **CAP_SYS_ADMIN** capability is permitted to mount cgroupfs, no questions asked. As a bonus, most containers today run without cgroup namespaces, meaning the mounted cgroup would be the root cgroup hosting and the **release_agent** file.

![AX](https://i.postimg.cc/3R7Dtky9/image.png)

> **Fig. 7** - In the initial cgroup namespace, mounting cgroupfs will always mount the root cgroup, regardless of the container's cgroup.

Even with the **CAP_SYS_ADMIN** capability, **AppArmor and SELinux** still prevent mounting, so containers running with either cannot exploit **CVE-2022-0492**. **Fig. 8** shows a container running without **AppArmor and SELinux**, and with the **CAP_SYS_ADMIN** capability, exploiting **CVE-2022-0492** to break out.

![ZY](https://i.postimg.cc/rmnF5s5D/image.png)

> **Fig. 8** - Exploiting **CVE-2022-0492** for container escape via the CAP_SYS_ADMIN capability.


# Conclusion

**CVE-2022-0492** marks another Linux vulnerability that can be exploited for container escape. Fortunately, environments that follow best practices are protected from this vulnerability. Environments with lax security controls hosting untrusted or publicly exposed containers are, unsurprisingly, at high risk. As always, it's best to upgrade your hosts to a fixed kernel version.

We strongly recommend running containers with **Seccomp** and either **AppArmor or SELinux** enabled, to protect against this vulnerability and against future Linux _zero-day vulnerabilities_. Many privilege escalation vulnerabilities in the Linux kernel can only be exploited for container escape when the container is allowed to create a new user namespace, or in other words, when the container runs without **Seccomp**.

© 2022 - **Not** Sofiane Hamlaooui - Making the world a better place 🌎
