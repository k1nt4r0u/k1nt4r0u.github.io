from pathlib import Path

BINARY_PATH = Path(__file__).with_name("forge")
RODATA_OFFSET = 0x2000
RODATA_END = 0x12CC8
MATRIX_OFFSET = 0x2080
VECTOR_OFFSET = 0x2040
ROW_COUNT = 56
ROW_WIDTH = 56
ROW_STRIDE = 0x38
TABLE_OFFSET = 0x2CC0
TABLE_SIZE = 0x10000


def load_rodata(binary_path: Path) -> bytes:
    data = binary_path.read_bytes()
    return data[RODATA_OFFSET:RODATA_END]


def mul(table: bytes, left: int, right: int) -> int:
    return table[(left << 8) | right]


def inverse(table: bytes, value: int) -> int:
    for candidate in range(1, 256):
        if mul(table, value, candidate) == 1:
            return candidate
    raise ValueError(f"no inverse for 0x{value:02x}")


def build_matrix(rodata: bytes) -> list[list[int]]:
    matrix_base = MATRIX_OFFSET - RODATA_OFFSET
    vector_base = VECTOR_OFFSET - RODATA_OFFSET
    rows = []

    for row_index in range(ROW_COUNT):
        start = matrix_base + row_index * ROW_STRIDE
        row = list(rodata[start:start + ROW_WIDTH])
        row.append(rodata[vector_base + row_index])
        rows.append(row)

    return rows


def reduce_matrix(rows: list[list[int]], table: bytes) -> bytes:
    for pivot in range(ROW_COUNT):
        pivot_row = pivot
        while pivot_row < ROW_COUNT and rows[pivot_row][pivot] == 0:
            pivot_row += 1

        if pivot_row == ROW_COUNT:
            raise ValueError(f"no pivot found for column {pivot}")

        if pivot_row != pivot:
            rows[pivot], rows[pivot_row] = rows[pivot_row], rows[pivot]

        pivot_value = rows[pivot][pivot]
        pivot_inverse = inverse(table, pivot_value)
        rows[pivot] = [mul(table, value, pivot_inverse) for value in rows[pivot]]

        for row_index in range(ROW_COUNT):
            if row_index == pivot:
                continue

            factor = rows[row_index][pivot]
            if factor == 0:
                continue

            rows[row_index] = [
                left ^ mul(table, factor, right)
                for left, right in zip(rows[row_index], rows[pivot])
            ]

    return bytes(row[-1] for row in rows)


def main() -> None:
    rodata = load_rodata(BINARY_PATH)
    table_base = TABLE_OFFSET - RODATA_OFFSET
    table = rodata[table_base:table_base + TABLE_SIZE]
    rows = build_matrix(rodata)
    flag = reduce_matrix(rows, table).decode("ascii")
    print(flag)


if __name__ == "__main__":
    main()
