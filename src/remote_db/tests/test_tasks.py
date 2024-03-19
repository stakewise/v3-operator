from src.remote_db.tasks import _get_key_indexes


def test_get_key_indexes():
    assert _get_key_indexes(1, 1, 0) == (0, 1)

    assert _get_key_indexes(2, 1, 0) == (0, 2)

    assert _get_key_indexes(2, 2, 0) == (0, 1)
    assert _get_key_indexes(2, 2, 1) == (1, 2)

    assert _get_key_indexes(27, 2, 0) == (0, 14)
    assert _get_key_indexes(27, 2, 1) == (14, 27)

    assert _get_key_indexes(150, 3, 0) == (0, 50)
    assert _get_key_indexes(150, 3, 1) == (50, 100)
    assert _get_key_indexes(150, 3, 2) == (100, 150)

    total = 50
    count = 0
    for i in range(total):
        if i == 49:
            assert _get_key_indexes(199, total, i) == (196, 199)
        else:
            assert _get_key_indexes(199, total, i) == (i * 4, i * 4 + 4)
        count += _get_key_indexes(199, total, i)[1] - _get_key_indexes(199, total, i)[0]
    assert count == 199
