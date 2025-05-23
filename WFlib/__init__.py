import shutil

def check_dependency():
    # required_software = ['geckodriver', 'tshark']
    required_software = ['tshark']
    for software in required_software:
        if shutil.which(software) is None:
            raise RuntimeError(f"{software} is required but not found.")
        
# Call check_dependency() at the beginning of your script.
check_dependency()