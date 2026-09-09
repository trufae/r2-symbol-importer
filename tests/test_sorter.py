from r2_symbol_importer.core.sorter import sort_type_definitions


def test_sort_type_definitions_order():
    types = [
        "typedef struct _B { struct _A a; int b_val; } B;",
        "typedef struct _A { int a_val; } A;",
    ]
    sorted_res = sort_type_definitions(types)
    assert len(sorted_res) == 2
    # Struct A must come before struct B
    assert "struct _A" in sorted_res[0]
    assert "struct _B" in sorted_res[1]


def test_sort_three_level_dependency():
    types = [
        "typedef struct _C { B b_instance; } C;",
        "typedef struct _A { int x; } A;",
        "typedef struct _B { A a_instance; } B;",
    ]
    sorted_res = sort_type_definitions(types)
    assert len(sorted_res) == 3
    # Order must be A -> B -> C
    assert "struct _A" in sorted_res[0]
    assert "struct _B" in sorted_res[1]
    assert "struct _C" in sorted_res[2]


def test_sort_cycle_tolerance():
    # Mutual pointer references shouldn't crash
    types = [
        "typedef struct _NODE1 { struct _NODE2 *next; } NODE1;",
        "typedef struct _NODE2 { struct _NODE1 *prev; } NODE2;",
    ]
    sorted_res = sort_type_definitions(types)
    assert len(sorted_res) == 2
