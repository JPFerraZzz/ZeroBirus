"""Helper that builds a typical SystemContext for tests."""

from zerobirus.core.safety import SystemContext

OD = r"C:\Users\Ana\OneDrive"
# Portuguese Windows with OneDrive folder backup: localised names inside OneDrive. The
# backend must pass these in personal_folders (SHGetKnownFolderPath); safety cannot guess.
ONEDRIVE_PT_FOLDERS = (
    OD + r"\Ambiente de Trabalho",
    OD + r"\Documentos",
    OD + r"\Imagens",
)


def typical_context(
    *,
    system_root: str = r"C:\Windows",
    program_files: tuple[str, ...] = (r"C:\Program Files", r"C:\Program Files (x86)"),
    program_data: str = r"C:\ProgramData",
    users_dir: str = r"C:\Users",
    profile_roots: tuple[str, ...] = (r"C:\Users\Ana",),
    personal_folders: tuple[str, ...] = (*ONEDRIVE_PT_FOLDERS, r"D:\Dados\Docs"),
    own_pids: frozenset[int] = frozenset(),
) -> SystemContext:
    """Typical machine: user Ana, OneDrive in Portuguese, Documents also relocated to D:."""
    return SystemContext(
        system_root=system_root,
        program_files=program_files,
        program_data=program_data,
        users_dir=users_dir,
        profile_roots=profile_roots,
        personal_folders=personal_folders,
        own_pids=own_pids,
    )
