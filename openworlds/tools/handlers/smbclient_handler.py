"""Smbclient handler — simulates SMB share enumeration and file access."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler


class SmbclientHandler(BaseHandler):
    """Simulates smbclient output for share enumeration and file reading."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated smbclient.

        Supports:
            smbclient -L //HOST -U user         List shares
            smbclient //HOST/SHARE -U user       Connect to share
            smbclient //HOST/SHARE -c 'ls'       List files
            smbclient //HOST/SHARE -c 'get FILE' Download file
        """
        if not args:
            return "Usage: smbclient //HOST/SHARE [options]"

        # Parse target
        target_str = args[0] if not args[0].startswith("-") else ""
        list_mode = "-L" in args

        if list_mode:
            # smbclient -L //HOST
            target = args[args.index("-L") + 1] if "-L" in args else ""
            target = target.strip("/\\")
            return self._list_shares(target)

        if not target_str:
            return "Usage: smbclient //HOST/SHARE [options]"

        # Parse //HOST/SHARE
        parts = target_str.strip("/\\").split("/")
        if len(parts) < 1:
            return "Error: Invalid target format"

        hostname = parts[0]
        share_name = parts[1] if len(parts) > 1 else None

        # Parse -c command
        cmd = ""
        for i, arg in enumerate(args):
            if arg == "-c" and i + 1 < len(args):
                cmd = args[i + 1].strip("'\"")

        host = self.find_host(hostname)
        if not host:
            return f"Connection to {hostname} failed (Error NT_STATUS_HOST_UNREACHABLE)"

        if not share_name:
            return self._list_shares(hostname)

        # Find the share
        share = next(
            (s for s in host.shares if s.name.lower() == share_name.lower()),
            None,
        )
        if not share:
            return f"tree connect failed: NT_STATUS_BAD_NETWORK_NAME"

        if cmd.startswith("get "):
            filename = cmd[4:].strip()
            return self._get_file(share, filename)
        elif cmd in ("ls", "dir"):
            return self._list_files(share)
        else:
            return self._list_files(share)

    def _list_shares(self, hostname: str) -> str:
        """List all shares on a host."""
        host = self.find_host(hostname)
        if not host:
            return f"Connection to {hostname} failed (Error NT_STATUS_HOST_UNREACHABLE)"

        lines = [
            f"",
            f"\tSharename       Type      Comment",
            f"\t---------       ----      -------",
        ]
        for share in host.shares:
            stype = "Disk" if share.name not in ("IPC$",) else "IPC"
            lines.append(f"\t{share.name:<15} {stype:<9} ")

        lines.extend([
            f"Reconnecting with SMB1 for workgroup listing.",
            f"",
        ])
        return "\n".join(lines)

    def _list_files(self, share: object) -> str:
        """List files in a share."""
        lines = [
            f"  .                                   D        0  Mon Jan 15 14:30:00 2024",
            f"  ..                                  D        0  Mon Jan 15 14:30:00 2024",
        ]
        for f in share.files:  # type: ignore
            size = len(f.content)
            lines.append(
                f"  {f.name:<37} A  {size:>6}  Mon Jan 15 14:30:00 2024"
            )

        total_files = len(share.files) + 2  # type: ignore
        lines.extend([
            f"",
            f"\t\t{total_files} files, 1073741824 bytes free",
        ])
        return "\n".join(lines)

    def _get_file(self, share: object, filename: str) -> str:
        """Simulate downloading a file — returns file content."""
        for f in share.files:  # type: ignore
            if f.name.lower() == filename.lower():
                return (
                    f"getting file \\{f.name} as {f.name} "
                    f"({len(f.content)} bytes)\n\n"
                    f"--- File Content ---\n"
                    f"{f.content}"
                )
        return f"NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \\{filename}"
