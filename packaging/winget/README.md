# winget distribution (release-prep draft, 2026-11-10)

> Manifests here are TEMPLATES. They become submittable only after the
> first signed public release (owner gate: PFX re-key + release). Per the
> composite vision tracker row 12.

## Plan

1. First public release: signed installer + portable zip on GitHub
   Releases (asset URLs + SHA256 required by winget).
2. Fill the two templates below with real versions/hashes.
3. Submit a PR to `microsoft/winget-pkgs`:
   - `manifests/h/HenryPlus/simplewall-composite/<version>/` (installer)
   - InstallerType: inno (setup exe) and a second `portable` entry (zip)
4. Automate: update the manifest version + InstallerUrl + SHA256 in the
   release CI after the release job finishes.

## Installer manifest template (singleton)

```yaml
PackageIdentifier: HenryPlus.simplewall-composite
PackageVersion: <VERSION>
PackageName: simplewall (composite)
Publisher: PhilopaterSh
License: GPL-3.0
LicenseUrl: https://github.com/PhilopaterSh/simplewall/blob/main/LICENSE
ShortDescription: Ultra-light per-application WFP firewall (composite fork of simplewall)
PackageUrl: https://github.com/PhilopaterSh/simplewall
Installers:
  - Architecture: x64
    InstallerUrl: <RELEASE_ASSET_URL setup exe>
    InstallerType: inno
    InstallerSha256: <SHA256>
    InstallerSwitches:
      Silent: /VERYSILENT /NORESTART
      SilentWithProgress: /SILENT /NORESTART
ManifestType: singleton
ManifestVersion: 1.6.0
```

## Portable entry (delta)

```yaml
  - Architecture: x64
    InstallerUrl: <RELEASE_ASSET_URL zip>
    InstallerType: zip
    NestedInstallerType: portable
    NestedInstallerFiles:
      - RelativeFilePath: simplewall.exe
    InstallerSha256: <SHA256>
```

## Validation before submission

```powershell
winget validate <manifest-path>
```
