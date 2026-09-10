import os
import importlib
from colorama import init, Fore, Style
import time
from confs import set_configs

init(autoreset=True)

if os.getuid() != 0:
    print(f'{Fore.LIGHTYELLOW_EX}Run it as root')
    exit()

def main():
    while True:
        os.system('clear')
        color = Fore.LIGHTGREEN_EX
        reset = Style.RESET_ALL
        print(
            f"{color}{'01. SCANNERS':<25}"
            f"{color}{'02. CONFS':<25}{color}03. EXIT{reset}"
        )
        try:
            choice = input(f'$: ')
        except KeyboardInterrupt:
            os.system('clear')
            exit()
        if choice == '1':
            import scanners.scanning
            importlib.reload(scanners.scanning)
        elif choice == '2':
            os.system('clear')
            try:
                color = Fore.BLUE
                reset = Style.RESET_ALL
                os.system('clear')
                set_configs()
            except KeyboardInterrupt:
                continue
        elif choice == '3':
            os.system('clear')
            exit()
        else:
            print(f"{Fore.YELLOW}bad input")
            time.sleep(2)
            continue

main()
