// Fixture: CWE-94 Code Injection - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: script_engine_eval_llm_output
// SOURCE: llm_response
// SINK: ScriptEngine.eval
// TAINT_HOPS: 1
// NOTES: LangChain4j-style LLM generates code, evaluated by ScriptEngine
import javax.script.*;

public class TpScriptEngineEvalLlm {
    public Object executeGenerated(String llmCode) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        // VULNERABLE: LLM-generated code executed directly
        return engine.eval(llmCode);
    }
}
