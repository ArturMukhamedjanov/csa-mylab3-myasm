import contextlib
import io
import logging
import os
import tempfile

import machine as machine
import translator as translator
import pytest

def normalize_whitespace(s):
    return ' '.join(s.split())

@pytest.mark.golden_test("golden/*.yml")
def test_translator_and_machine(golden, caplog):
    caplog.set_level(logging.INFO)

    # Создаём временную папку для тестирования приложения.
    with tempfile.TemporaryDirectory() as tmpdirname:
        # Готовим имена файлов для входных и выходных данных.
        source = os.path.join(tmpdirname, "source.myasm")
        input_stream = os.path.join(tmpdirname, "input.txt")
        target = os.path.join(tmpdirname, "target.o")

        # Записываем входные данные в файлы. Данные берутся из теста.
        with open(source, "w", encoding="utf-8") as file:
            file.write(golden["in_source"])
        with open(input_stream, "w", encoding="utf-8") as file:
            file.write(golden["in_stdin"])

        # Запускаем транслятор и собираем весь стандартный вывод в переменную
        # stdout
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            translator.main(source, target)
            print("============================================================")
            machine.main(target, input_stream)

        # Выходные данные также считываем в переменные.
        with open(target + ".debug", encoding="utf-8") as file:
            code = file.read()

        with open("log.txt", "w", encoding="utf-8") as log_file:
            log_file.write(caplog.text)

        # Проверяем, что ожидания соответствуют реальности.
        assert code == golden.out["out_code_debug"]
        assert stdout.getvalue() == golden.out["out_stdout"]
        assert normalize_whitespace(caplog.text) == normalize_whitespace(golden.out["out_log"])
