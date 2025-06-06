// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// attachCgroup and detachCgroup have to deal with two different kernel APIs:
//
// bpf_link (available with kernel version >= 5.7): in order for the program<->cgroup
// association to outlive the userspace process, the link (not the program) needs to be pinned.
// Removing the pinned link on bpffs breaks the association.
// Cilium will only use links on fresh installs and if available in the kernel.
// On upgrade, a link can be updated using link.Update(), which will atomically replace the
// currently running bpf program.
//
// PROG_ATTACH (all kernel versions pre 5.7 that cilium supports): by definition the association
// outlives userspace as the cgroup will hold a reference  to the attached program and detaching
// must be done explicitly using PROG_DETACH.
// This API is what cilium has been using prior to the 1.14 release and will continue to use if
// bpf_link is not available.
// On upgrade, cilium will continue to seamlessly replace old programs with the PROG_ATTACH API,
// because updating it with a bpf_link could cause connectivity interruptions.

package socketlb

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var attachTypes = map[string]ebpf.AttachType{
	Connect4:     ebpf.AttachCGroupInet4Connect,
	SendMsg4:     ebpf.AttachCGroupUDP4Sendmsg,
	RecvMsg4:     ebpf.AttachCGroupUDP4Recvmsg,
	GetPeerName4: ebpf.AttachCgroupInet4GetPeername,
	PostBind4:    ebpf.AttachCGroupInet4PostBind,
	PreBind4:     ebpf.AttachCGroupInet4Bind,
	Connect6:     ebpf.AttachCGroupInet6Connect,
	SendMsg6:     ebpf.AttachCGroupUDP6Sendmsg,
	RecvMsg6:     ebpf.AttachCGroupUDP6Recvmsg,
	GetPeerName6: ebpf.AttachCgroupInet6GetPeername,
	PostBind6:    ebpf.AttachCGroupInet6PostBind,
	PreBind6:     ebpf.AttachCGroupInet6Bind,
	SockRelease:  ebpf.AttachCgroupInetSockRelease,
}

// attachCgroup attaches a program from spec with the given name to cgroupRoot.
// If the kernel supports it, the resulting bpf_link is pinned to pinPath.
//
// Upgrades from prior Cilium versions will continue to be handled by a PROG_ATTACH
// to replace an old program attached to a cgroup.
func attachCgroup(logger *slog.Logger, spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	prog := spec.Programs[name]
	if prog == nil {
		return fmt.Errorf("program %s not found in ELF", name)
	}

	scopedLog := logger.With(
		logfields.Name, name,
	)

	// Attempt to open and update an existing link.
	pin := filepath.Join(pinPath, name)
	err := bpf.UpdateLink(pin, prog)
	switch {
	// Update successful, nothing left to do.
	case err == nil:
		scopedLog.Info("Updated link for program",
			logfields.Pin, pin,
		)

		return nil

	// Link exists, but is defunct, and needs to be recreated against a new
	// cgroup. This can happen in environments like dind where we're attaching
	// to a sub-cgroup that goes away if the container is destroyed, but the
	// link persists in the host's /sys/fs/bpf. The program no longer gets
	// triggered at this point and the link needs to be removed to proceed.
	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		scopedLog.Info("Unpinned defunct link for program",
			logfields.Pin, pin,
		)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		scopedLog.Info("No existing link found for program",
			logfields.Pin, pin,
		)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, name, err)
	}

	cg, err := os.Open(cgroupRoot)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cgroupRoot, err)
	}
	defer cg.Close()

	// Create a new link. This will only succeed on nodes that support bpf_link
	// and don't have any attached PROG_ATTACH programs.
	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	})
	if err == nil {
		defer func() {
			// The program was successfully attached using bpf_link. Closing a link
			// does not detach the program if the link is pinned.
			if err := l.Close(); err != nil {
				scopedLog.Warn("Failed to close bpf_link for program")
			}
		}()

		if err := l.Pin(pin); err != nil {
			return fmt.Errorf("pin link at %s for program %s : %w", pin, name, err)
		}

		// Successfully created and pinned bpf_link.
		scopedLog.Debug("Program attached using bpf_link")

		return nil
	}

	// Kernels before 5.7 don't support bpf_link. In that case link.AttachRawLink
	// returns ErrNotSupported.
	//
	// If the kernel supports bpf_link, but an older version of Cilium attached a
	// cgroup program without flags (old init.sh behaviour), link.AttachRawLink
	// will return EPERM because bpf_link implicitly uses the multi flag.
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, link.ErrNotSupported) {
		// Unrecoverable error from AttachRawLink.
		return fmt.Errorf("attach program %s using bpf_link: %w", name, err)
	}

	scopedLog.Debug("Performing PROG_ATTACH for program")

	// Call PROG_ATTACH without flags to attach the program if bpf_link is not
	// available or a previous PROG_ATTACH without flags has to be seamlessly
	// replaced.
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	}); err != nil {
		return fmt.Errorf("PROG_ATTACH for program %s: %w", name, err)
	}

	// Nothing left to do, the cgroup now holds a reference to the prog
	// so we don't need to hold a reference in the agent/bpffs to ensure
	// the program stays active.
	scopedLog.Debug("Program was attached using PROG_ATTACH")

	return nil

}

// detachCgroup detaches a program with the given name from cgroupRoot. Attempts
// to open a pinned link with the given name from directory pinPath first,
// falling back to PROG_DETACH if no pin is present.
func detachCgroup(logger *slog.Logger, name, cgroupRoot, pinPath string) error {
	pin := filepath.Join(pinPath, name)
	err := bpf.UnpinLink(pin)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		// The pinned link exists, something went wrong unpinning it.
		return fmt.Errorf("unpinning cgroup program using bpf_link: %w", err)
	}

	// No bpf_link pin found, detach all prog_attach progs.
	logger.Debug("No pinned link, querying cgroup", logfields.Pin, pin)
	err = detachAll(logger, attachTypes[name], cgroupRoot)
	// Treat detaching unsupported attach types as successful.
	if errors.Is(err, link.ErrNotSupported) {
		return nil
	}
	return err
}

// detachAll detaches all programs attached to cgroupRoot with the corresponding attach type.
func detachAll(logger *slog.Logger, attach ebpf.AttachType, cgroupRoot string) error {
	cg, err := os.Open(cgroupRoot)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cgroupRoot, err)
	}
	defer cg.Close()

	// Query the program ids of all programs currently attached to the given cgroup
	// with the given attach type. In ciliums case this should always return only one id.
	ids, err := link.QueryPrograms(link.QueryOptions{
		Target: int(cg.Fd()),
		Attach: attach,
	})
	// We know the cgroup root exists, so EINVAL will likely mean querying
	// the given attach type is not supported.
	if errors.Is(err, unix.EINVAL) {
		err = fmt.Errorf("%w: %w", err, link.ErrNotSupported)
	}
	// Even though the cgroup exists, QueryPrograms will return EBADF
	// on a cgroupv1.
	if errors.Is(err, unix.EBADF) {
		logger.Debug("The cgroup exists but is a cgroupv1. No detachment necessary")
		return nil
	}
	if err != nil {
		return fmt.Errorf("query cgroup %s for type %s: %w", cgroupRoot, attach, err)
	}
	if ids == nil || len(ids.Programs) == 0 {
		logger.Debug("No programs in cgroup with attach type",
			logfields.Root, cgroupRoot,
			logfields.Type, attach,
		)
		return nil
	}

	// cilium owns the cgroup and assumes only one program is attached.
	// This allows to remove all ids returned in the query phase.
	for _, id := range ids.Programs {
		prog, err := ebpf.NewProgramFromID(id.ID)
		if err != nil {
			return fmt.Errorf("could not open program id %d: %w", id, err)
		}
		defer prog.Close()

		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  int(cg.Fd()),
			Program: prog,
			Attach:  attach,
		}); err != nil {
			return fmt.Errorf("detach programs from cgroup %s attach type %s: %w", cgroupRoot, attach, err)
		}

		logger.Debug("Detached program id",
			logfields.ID, id,
		)
	}

	return nil
}
