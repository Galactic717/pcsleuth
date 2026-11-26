; Hooks for the Tauri NSIS installer. scripts/package-release.ps1 passes this file to Tauri as
; bundle.windows.nsis.installerHooks.
;
; The installer never registers the recorder service: that stays the user's opt-in (ADR 0006), made
; later with `pcsleuth-recorder install` from the install folder, which is why the install is per
; machine (the service refuses to register from outside Program Files). It adds nothing to PATH:
; NSIS has no safe way to edit a long PATH (strings stop at 1024 characters) and Tauri's NSIS does
; not bundle the EnVar plugin, so the exes are run from the install folder or the Start menu.

!macro NSIS_HOOK_PREUNINSTALL
  ; Uninstall removes what the user turned on: the recorder service and its ring file. An upgrade
  ; runs this uninstaller with /UPDATE, and then the opt-in stays as it was.
  ${If} $UpdateMode <> 1
  ${AndIf} ${FileExists} "$INSTDIR\pcsleuth-recorder.exe"
    ; Hidden, and the result is ignored: "not installed" is an answer, not a failure here.
    nsExec::ExecToLog '"$INSTDIR\pcsleuth-recorder.exe" uninstall'
    Pop $0
  ${EndIf}
!macroend
