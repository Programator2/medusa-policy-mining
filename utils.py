from collections.abc import Iterator


def path_components(path: str) -> Iterator[str]:
    """Parse a path and return its components as iterator.

    :param path: string in the form of `/this/is/a/path`. It has to start with a
    `/` and optionally end with a `/`
    """
    return filter(lambda x: bool(x), path.split('/'))
