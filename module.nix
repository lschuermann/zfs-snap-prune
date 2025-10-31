{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.zfs-snap-prune;

  # `buildAllowCommand` and `buildUnallowCommand` functions taken from the
  # upstream NixOS syncoid module: `nixos/modules/services/backup/syncoid.nix`,
  # revision 033d8a06340c048f00071163f030678d3ab7fecd.

  # Function to build "zfs allow" commands for the filesystems we've delegated
  # permissions to. It also checks if the target dataset exists before
  # delegating permissions, if it doesn't exist we delegate it to the parent
  # dataset (if it exists). This should solve the case of provisoning new
  # datasets.
  buildAllowCommand =
    permissions: dataset:
    (
      "-+${pkgs.writeShellScript "zfs-allow-${dataset}" ''
        # Here we explicitly use the booted system to guarantee the stable API needed by ZFS

        # Run a ZFS list on the dataset to check if it exists
        if ${
          lib.escapeShellArgs [
            "/run/booted-system/sw/bin/zfs"
            "list"
            dataset
          ]
        } 2> /dev/null; then
          ${lib.escapeShellArgs [
            "/run/booted-system/sw/bin/zfs"
            "allow"
            cfg.user
            (concatStringsSep "," permissions)
            dataset
          ]}
        ${lib.optionalString ((builtins.dirOf dataset) != ".") ''
          else
            ${lib.escapeShellArgs [
              "/run/booted-system/sw/bin/zfs"
              "allow"
              cfg.user
              (concatStringsSep "," permissions)
              # Remove the last part of the path
              (builtins.dirOf dataset)
            ]}
        ''}
        fi
      ''}"
    );

  # Function to build "zfs unallow" commands for the filesystems we've
  # delegated permissions to. Here we unallow both the target but also
  # on the parent dataset because at this stage we have no way of
  # knowing if the allow command did execute on the parent dataset or
  # not in the pre-hook. We can't run the same if in the post hook
  # since the dataset should have been created at this point.
  buildUnallowCommand =
    permissions: dataset:
    (
      "-+${pkgs.writeShellScript "zfs-unallow-${dataset}" ''
        # Here we explicitly use the booted system to guarantee the stable API needed by ZFS
        ${lib.escapeShellArgs [
          "/run/booted-system/sw/bin/zfs"
          "unallow"
          cfg.user
          (concatStringsSep "," permissions)
          dataset
        ]}
        ${lib.optionalString ((builtins.dirOf dataset) != ".") (
          lib.escapeShellArgs [
            "/run/booted-system/sw/bin/zfs"
            "unallow"
            cfg.user
            (concatStringsSep "," permissions)
            # Remove the last part of the path
            (builtins.dirOf dataset)
          ]
        )}
      ''}"
    );
in
{

  # Interface

  options.services.zfs-snap-prune = {
    enable = mkEnableOption (lib.mdDoc "ZFS snap prune service");

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./default.nix { };
    };

    interval = mkOption {
      type = types.str;
      default = "hourly";
      example = "*-*-* *:15:00";
      description = lib.mdDoc ''
        Run zfs-snap-prune at this interval. The default is to run hourly.

        The format is described in
        {manpage}`systemd.time(7)`.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "zfssnapprune";
      example = "backup";
      description = lib.mdDoc ''
        The user for the service. ZFS privilege delegation will be
        automatically configured for any local pools used by zfs-snap-prune if
        this option is set to a user other than root. The user will be given
        the "hold" and "send" privileges on any pool that has datasets being
        sent and the "create", "mount", "receive", and "rollback" privileges on
        any pool that has datasets being received.
      '';
    };

    group = mkOption {
      type = types.str;
      default = "zfssnapprune";
      example = "backup";
      description = lib.mdDoc "The group for the service.";
    };

    zfsPermissions = mkOption {
      type = types.listOf types.str;
      default = [
        "mount"
        "destroy"
      ];
      description = lib.mdDoc ''
        Permissions granted for the {option}`services.zfs-snap-prune.user` user
        for local source datasets. See
        <https://openzfs.github.io/openzfs-docs/man/8/zfs-allow.8.html>
        for available permissions.
      '';
    };

    jobs = mkOption {
      type = types.listOf types.attrs;
    };

    mode = mkOption {
      type = types.str;
    };
  };

  # Implementation

  config = mkIf cfg.enable {
    users = {
      users = mkIf (cfg.user == "zfssnapprune") {
        zfssnapprune = {
          group = cfg.group;
          isSystemUser = true;
          home = "/var/empty";
          createHome = false;
        };
      };
      groups = mkIf (cfg.group == "zfssnapprune") {
        zfssnapprune = { };
      };
    };

    systemd.services.zfs-snap-prune = {
      description = "ZFS snap prune service";
      after = [ "zfs.target" ];
      startAt = cfg.interval;
      serviceConfig = {
        ExecStartPre = (map (job: buildAllowCommand cfg.zfsPermissions job.pool) cfg.jobs);
        ExecStopPost = (map (job: buildUnallowCommand cfg.zfsPermissions job.pool) cfg.jobs);
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/zfs-snap-prune"
          "--config"
          (pkgs.writeText "zfs-snap-prune-config.yml" (
            builtins.toJSON {
              mode = cfg.mode;
              jobs = cfg.jobs;
            }
          ))
        ];
        User = cfg.user;
        Group = cfg.group;
        PrivateTmp = true;
        # The following options are only for optimizing:
        # systemd-analyze security | grep zfs-snap-prune
        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DeviceAllow = [ "/dev/zfs" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateMounts = true;
        PrivateNetwork = mkDefault false;
        PrivateUsers = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = [ ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RootDirectory = "/run/zfs-snap-prune";
        RootDirectoryStartOnly = true;
        BindPaths = [ "/dev/zfs" ];
        BindReadOnlyPaths = [
          builtins.storeDir
          "/etc"
          "/run"
          "/bin/sh"
        ];
        # Avoid useless mounting of RootDirectory= in the own RootDirectory= of ExecStart='s mount namespace.
        InaccessiblePaths = [ "-+/run/zfs-snap-prune" ];
        MountAPIVFS = true;
        # Create RootDirectory= in the host's mount namespace.
        RuntimeDirectory = [ "zfs-snap-prune" ];
        RuntimeDirectoryMode = "700";
        SystemCallFilter = [
          "@system-service"
          # Groups in @system-service which do not contain a syscall listed by:
          # perf stat -x, 2>perf.log -e 'syscalls:sys_enter_*' syncoid …
          # awk >perf.syscalls -F "," '$1 > 0 {sub("syscalls:sys_enter_","",$3); print $3}' perf.log
          # systemd-analyze syscall-filter | grep -v -e '#' | sed -e ':loop; /^[^ ]/N; s/\n //; t loop' | grep $(printf ' -e \\<%s\\>' $(cat perf.syscalls)) | cut -f 1 -d ' '
          "~@aio"
          "~@chown"
          "~@keyring"
          "~@memlock"
          "~@privileged"
          "~@resources"
          "~@setuid"
          "~@timer"
        ];
        SystemCallArchitectures = "native";
        # This is for BindPaths= and BindReadOnlyPaths=
        # to allow traversal of directories they create in RootDirectory=.
        UMask = "0066";
      };
    };
  };
}
