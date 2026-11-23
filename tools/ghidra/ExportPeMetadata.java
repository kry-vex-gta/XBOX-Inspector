// Export static metadata for an explicitly selected test or authorized PE.
// @category XBOX-Inspector

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

public class ExportPeMetadata extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema", "xbox-inspector-ghidra-metadata/1");
        result.put("ghidra_version", Application.getApplicationVersion());
        result.put("format", currentProgram.getExecutableFormat());
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("ghidra_source_sha256", currentProgram.getExecutableSHA256());
        result.put("image_base", currentProgram.getImageBase().toString());
        result.put("memory_blocks", currentProgram.getMemory().getBlocks().length);
        result.put("guest_executed", false);
        Files.writeString(Path.of(getScriptArgs()[0]), new Gson().toJson(result) + "\n",
                          StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
}
