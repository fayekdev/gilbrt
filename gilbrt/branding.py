"""Static, responsive ASCII branding for real terminal sessions."""

from rich.console import Console
from rich.text import Text

LIME = "#a8d65c"
HAT = "#929b99"
FACE = "#f3f7ed"

# The supplied mascot, with background dots replaced by transparent spaces.
_MASCOT = (
    "                                    -=*##%%%%%%%%##*=:",
    "                               =#%%%%%%%%%%%%%%%%%%%%%%%%*-",
    "                           -*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%+",
    "                        :*%%%%%%%%%%%%%%%%%%=:*%%%%%%%%%%%%%%%%#=",
    "                      -#%%%%%%%%%%*#%%%%%%%#: -%%%%%%%%*#%%%%%%%%%+",
    "                    :#%%%%%%%%%+:  =%%%%%%%#: -%%%%%%%*:  -#%%%%%%%%-",
    "                   *%%%%%%%%+:  :*%%%%%%%%%#: -%%%%%%%%%#=   =#%%%%%%*",
    "                 :#%%%%%%%#   -#%%%%%%%%%%%#: -%%%%%%%%%%%%=  :#%%%%%%%:",
    "                -%%%%%%%%%%%*-  :+%%%%%%%%%#: -%%%%%%%%%+:  -*%%%%%%%%%%=",
    "               -%%%%%%%%%%%%%%%*-  *%%%%%%%#: -%%%%%%%%: -*%%%%%%%%%%%%%%-",
    "              :%%%%%%%%%%%%%%%%%%%%%%%%%%%%%=:*%%%%%%%%%%%%%%%%%%%%%%%%%%%-",
    "              #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#",
    "             *%%%%%%%%%%%%%##################################%%%%%%%%%%%%%%#",
    "         :*%%%%%%%%##################################################%%%%%%%%%+",
    "       *%%%%%%#############################%%%%###########################%%%%%%#",
    "     *%%%%%################%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%###############%%%%%-",
    "    *%%%############%%%%%%%%%%%%%%##*+==--::::---=+*###%%%%%%%%%%%%%%%#########%%%#",
    "    #%%%#####%%%%%%%%%%%#*-:                                :=*%%%%%%%%%%%%%%%%%%%*",
    "    =%%%%%%%%%%%%%#=                                               :+%%%%%%%%%%%%+",
    "      :#%%%%%%%%=                                                      -%%%%%+-",
    "         :%%%%*              :#%%%*:                                    :#%%%%:",
    "        -%%%%=                =%%%%%%%=                                   +%%%%=",
    "       =%%%%-                    -#%%%%%%*:                                -%%%%+",
    "      =%%%%-                       =#%%%%%-                                 =%%%%=",
    "     :%%%%:                    :+%%%%%%*-                                    =%%%%-",
    "     %%%%=                   :#%%%%#=:        -++++++++++++-                  *%%%#",
    "    *%%%#                     =#*-           -%%%%%%%%%%%%%%=                 :%%%%-",
    "    #%%%-                                     :------------:                   *%%%*",
    "    %%%%:                                                                      +%%%*",
    "    %%%%-                                                                      *%%%*",
    "    #%%%*                                                                     :%%%%-",
    "    -%%%%+                                                                   :#%%%#",
    "     =%%%%#:                                                                -%%%%#",
    "      -%%%%%#-                                                            =#%%%%#",
    "        *%%%%%%%*=:                                                  :-+%%%%%%%-",
    "          =#%%%%%%%-              =**++===------====+=               +%%%%%%+",
    "              -#%%%#:            *%%%%%%%%%%%%%%%%%%%%#:            -%%%%-",
    "                #%%%%#=::  :::=#%%%%%###%%%%%%%%%%#%%%%%%+::    ::+%%%%%+",
    "                 +%%%%%%%%%%%%%%%%%+                =%%%%%%%%%%%%%%%%%#:",
    "                   :*%%%%%%%%%%#+                      =#%%%%%%%%%%#=",
)

# Original outline lettering; raw strings keep the diagonals single-width.
_WORDMARK = (
    r"       _ _ _          _   ",
    r"  __ _(_) | |__  _ __| |_ ",
    r" / _` | | | '_ \| '__| __|",
    r"| (_| | | | |_) | |  | |_ ",
    r" \__, |_|_|_.__/|_|   \__|",
    r" |___/                    ",
)
# Shorten the silhouette by 20%, retaining the detailed hat marks and entire face.
_DISPLAY_ROWS = tuple(row for row in range(len(_MASCOT)) if row not in {1, 10, 11, 14, 28, 29, 30, 32})
_LEFT_PADDING = min(len(row) - len(row.lstrip()) for row in _MASCOT)
_FULL_WIDTH = max(map(len, _MASCOT)) - _LEFT_PADDING

_TINY = (
    "      .-------.",
    "     / < | >   \\",
    "   _/===========\\_",
    "  /%%           %%\\",
    " |%%     >_      %%|",
    " |%%             %%|",
    "  \\%%           %%/",
    "   \\%%%%   %%%%/",
    "      '-----'",
)


def _color(row: int, column: int, char: str) -> str:
    if 20 <= row <= 27 and 24 <= column <= 64:
        return FACE
    if 3 <= row <= 10 and 27 <= column <= 64 and char not in "%#":
        return LIME
    return HAT if row <= 19 else LIME


def _art(full: bool) -> list[Text]:
    """Keep source-width detail in the shorter silhouette; reduce on narrow terminals."""
    step = 1 if full else 2
    width = max(map(len, _MASCOT))
    weight = {"%": 6, "#": 6, "*": 5, "+": 4, "=": 4, "-": 3, ":": 2}
    result = []
    for offset in range(0, len(_DISPLAY_ROWS), step):
        line = Text()
        for column in range(_LEFT_PADDING, width, step):
            cells = [
                (y, x, _MASCOT[y][x])
                for y in _DISPLAY_ROWS[offset:offset + step]
                for x in range(column, min(column + step, len(_MASCOT[y])))
                if _MASCOT[y][x] != " "
            ]
            if not cells:
                line.append(" ")
                continue
            y, x, char = max(cells, key=lambda cell: weight.get(cell[2], 1))
            line.append(char, style=_color(y, x, char))
        result.append(line)
    return result


def print_startup(console: Console) -> None:
    """Show a colored blob and name without adding art to piped/script output."""
    if not console.is_terminal:
        return
    width = console.width
    if width < 20:
        console.print(Text("gilbrt", style=f"bold {LIME}"), no_wrap=True, overflow="crop")
        return
    if width < 42:
        art = []
        for row, value in enumerate(_TINY):
            line = Text(value, style=HAT if row <= 2 else LIME)
            if ">_" in value:
                start = value.index(">_")
                line.stylize(FACE, start, start + 2)
            art.append(line)
    else:
        art = _art(full=width >= _FULL_WIDTH)
    art_width = max(line.cell_len for line in art)
    word_width = max(max(map(len, _WORDMARK)), len("A little CLI. A closer look."))
    beside = width >= art_width + 3 + word_width
    first = max(0, (len(art) - len(_WORDMARK)) // 2 - 1)
    console.print()
    for index, line in enumerate(art):
        if beside:
            line.append(" " * (art_width - line.cell_len + 3))
            if first <= index < first + len(_WORDMARK):
                line.append(_WORDMARK[index - first], style=f"bold {LIME}")
            elif index == first + len(_WORDMARK) + 1:
                line.append("A little CLI. A closer look.", style=HAT)
        console.print(line, no_wrap=True, overflow="crop", highlight=False)
    if not beside:
        console.print()
        if width >= word_width:
            indent = " " * ((width - max(map(len, _WORDMARK))) // 2)
            for row in _WORDMARK:
                console.print(Text(indent + row, style=f"bold {LIME}"), no_wrap=True, overflow="crop")
        else:
            console.print(Text("gilbrt", style=f"bold {LIME}"), no_wrap=True, overflow="crop")
    console.print()
