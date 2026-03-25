# Build Notes

Recommended for hardened production:
- Use `SplunkUtilityTool_v3_tk.spec` (Tk-only, onedir, UPX disabled).
- This build does not depend on PySide6/Qt at runtime.

Lab/experimental:
- `SplunkUtilityTool_v3.spec` bundles PySide6/Qt and is not recommended for hardened servers.
