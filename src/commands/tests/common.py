from src.commands.init import init


def generate_mnemonic(runner, vault) -> str:
    args_init = [
        '--language',
        'english',
        '--no-verify',
        '--vault',
        vault,
        '--network',
        'goerli',
    ]
    init_result = runner.invoke(init, args_init)
    return init_result.output.strip()
