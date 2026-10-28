# The RHEL-family clean box.
#
# almalinux:10 already carries curl, systemd and dnf. It does not carry gpg,
# which the installer needs, so gnupg2 is added, and firewalld because a
# RHEL-family server ships it and its 750 /etc/firewalld is what the
# installer's read grant exists for (record 4.176). sudo is added because the
# install command runs the agent through it, and this family's sudoers is the
# one whose secure_path leaves /usr/local/bin out (record 4.220), so the image
# has to carry the real one for that to be tested. acl is not added here on
# purpose: the package depends on it and the install has to bring it. No
# whichports anything is baked in, and everything under test arrives through
# the installer.
FROM almalinux:10
RUN dnf install -y --setopt=install_weak_deps=False gnupg2 systemd curl firewalld sudo \
 && dnf clean all
# systemd's own shutdown signal, so `docker stop` is a clean shutdown.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
