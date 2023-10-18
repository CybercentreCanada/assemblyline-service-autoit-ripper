import os
import subprocess

import autoit_ripper
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection


class AutoItRipper(ServiceBase):
    def __init__(self, config=None):
        super(AutoItRipper, self).__init__(config)

    def execute(self, request):
        result = Result()

        if request.file_type.startswith("executable/windows/"):
            content_list = autoit_ripper.extract(data=request.file_contents)
            if content_list:
                content = content_list[0][1].decode("utf-8")
                decompiled_script_path = os.path.join(self.working_directory, "script.au3")
                with open(decompiled_script_path, "w") as f:
                    f.write(content)
        # Only other option is code/a3x
        else:
            unautoit_bin_path = os.path.join(os.getcwd(), "UnAutoIt.bin")
            _ = subprocess.run(
                [unautoit_bin_path, "extract-all", "--output-dir", self.working_directory, request.file_path],
                capture_output=True,
                check=False,
            )

        was_decompiled_script_extracted = False
        for f in os.listdir(self.working_directory):
            if f.endswith(".au3"):
                request.add_extracted(os.path.join(self.working_directory, f), f, "Decompiled AutoIt script")
                was_decompiled_script_extracted = True

        if was_decompiled_script_extracted:
            if request.file_type.startswith("executable/windows/"):
                heur = Heuristic(1)
            else:
                heur = Heuristic(2)
            _ = ResultSection(heur.name, heur.description, heuristic=heur, parent=result)

        request.result = result
