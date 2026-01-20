// AI Security Test Cases - TypeScript
// INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
// Copyright © 2026 Sthenos Security. Test file only.

import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';
import { ChatOpenAI } from '@langchain/openai';
import { PromptTemplate } from '@langchain/core/prompts';
import { DynamicTool } from '@langchain/core/tools';
import { AgentExecutor, createOpenAIFunctionsAgent } from 'langchain/agents';
import { exec } from 'child_process';
import * as fs from 'fs';

// === LLM01: PROMPT INJECTION ===

// VULNERABLE: Direct user input in prompt
async function vulnerableDirectInput(userMessage: string): Promise<string> {
  const openai = new OpenAI();
  
  // BAD: User input directly in prompt
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: userMessage }  // Direct user input
    ]
  });
  
  return response.choices[0].message.content || '';
}

// VULNERABLE: Template literal injection
async function vulnerableTemplateLiteral(userQuery: string): Promise<string> {
  const anthropic = new Anthropic();
  
  // BAD: User input in template literal
  const prompt = `Answer this question: ${userQuery}`;
  
  const message = await anthropic.messages.create({
    model: 'claude-3-sonnet-20240229',
    max_tokens: 1024,
    messages: [{ role: 'user', content: prompt }]
  });
  
  return message.content[0].type === 'text' ? message.content[0].text : '';
}

// === LLM02: SENSITIVE DISCLOSURE ===

// VULNERABLE: API key in prompt
async function vulnerableApiKeyExposure(): Promise<string> {
  const openai = new OpenAI();
  
  // BAD: Hardcoded API key sent to model
  const apiKey = 'sk-1234567890abcdef';
  const prompt = `Use this API key: ${apiKey}`;
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  
  return response.choices[0].message.content || '';
}

// VULNERABLE: PII exposure
interface UserData {
  name: string;
  ssn: string;
  creditCard: string;
}

async function vulnerablePiiExposure(userData: UserData): Promise<string> {
  const openai = new OpenAI();
  
  // BAD: Raw PII sent to model
  const prompt = `Process customer: ${userData.name}, SSN: ${userData.ssn}, CC: ${userData.creditCard}`;
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  
  return response.choices[0].message.content || '';
}

// === LLM05: IMPROPER OUTPUT HANDLING ===

// VULNERABLE: Executing LLM output
async function vulnerableEvalOutput(prompt: string): Promise<any> {
  const openai = new OpenAI();
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  
  const code = response.choices[0].message.content || '';
  
  // BAD: Evaluating LLM output
  return eval(code);
}

// VULNERABLE: Shell execution from LLM output
async function vulnerableShellExecution(prompt: string): Promise<string> {
  const openai = new OpenAI();
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'Generate a shell command' },
      { role: 'user', content: prompt }
    ]
  });
  
  const command = response.choices[0].message.content || '';
  
  // BAD: Executing shell command from LLM
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

// VULNERABLE: HTML injection
async function vulnerableHtmlInjection(prompt: string): Promise<string> {
  const openai = new OpenAI();
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  
  const content = response.choices[0].message.content || '';
  
  // BAD: Direct HTML embedding
  return `<div>${content}</div>`;
}

// === LLM06: EXCESSIVE AGENCY ===

// VULNERABLE: Shell tool in LangChain
async function vulnerableShellTool(): Promise<AgentExecutor> {
  const llm = new ChatOpenAI();
  
  // BAD: Unrestricted shell access
  const shellTool = new DynamicTool({
    name: 'shell',
    description: 'Execute any shell command',
    func: async (command: string) => {
      return new Promise((resolve, reject) => {
        exec(command, (error, stdout) => {
          if (error) reject(error);
          else resolve(stdout);
        });
      });
    }
  });
  
  const tools = [shellTool];
  
  const agent = await createOpenAIFunctionsAgent({
    llm,
    tools,
    prompt: PromptTemplate.fromTemplate('You are a helpful assistant. {input}')
  });
  
  return new AgentExecutor({ agent, tools });
}

// VULNERABLE: File system tool
async function vulnerableFileSystemTool(): Promise<AgentExecutor> {
  const llm = new ChatOpenAI();
  
  // BAD: Unrestricted file access
  const writeTool = new DynamicTool({
    name: 'write_file',
    description: 'Write content to any file',
    func: async (input: string) => {
      const [path, content] = input.split('|||');
      fs.writeFileSync(path, content);  // BAD: No path validation
      return `Written to ${path}`;
    }
  });
  
  const deleteTool = new DynamicTool({
    name: 'delete_file',
    description: 'Delete any file',
    func: async (path: string) => {
      fs.unlinkSync(path);  // BAD: No validation
      return `Deleted ${path}`;
    }
  });
  
  const tools = [writeTool, deleteTool];
  
  const agent = await createOpenAIFunctionsAgent({
    llm,
    tools,
    prompt: PromptTemplate.fromTemplate('{input}')
  });
  
  return new AgentExecutor({ agent, tools });
}

// === MCP SECURITY ===

// VULNERABLE: MCP server with dangerous tools
class VulnerableMCPServer {
  tools: Record<string, any> = {};
  
  constructor() {
    // BAD: Dangerous tools registered
    this.tools['execute_shell'] = {
      name: 'execute_shell',
      description: 'Execute any shell command',
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string' }
        }
      }
    };
    
    this.tools['read_file'] = {
      name: 'read_file',
      description: 'Read any file',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string' }
        }
      }
    };
  }
  
  async handleToolCall(toolName: string, args: any): Promise<string> {
    if (toolName === 'execute_shell') {
      // BAD: Direct shell execution
      return new Promise((resolve, reject) => {
        exec(args.command, (err, stdout) => {
          if (err) reject(err);
          else resolve(stdout);
        });
      });
    }
    
    if (toolName === 'read_file') {
      // BAD: No path validation
      return fs.readFileSync(args.path, 'utf-8');
    }
    
    return 'Unknown tool';
  }
}

// === SAFE PATTERNS (should NOT trigger) ===

// SAFE: Sanitized input
async function safeInputHandling(userMessage: string): Promise<string> {
  const openai = new OpenAI();
  
  // GOOD: Sanitize input
  const sanitized = userMessage
    .replace(/[<>]/g, '')
    .substring(0, 1000);
  
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: sanitized }
    ]
  });
  
  return response.choices[0].message.content || '';
}

// SAFE: Restricted shell tool
async function safeRestrictedShell(): Promise<AgentExecutor> {
  const llm = new ChatOpenAI();
  
  const ALLOWED_COMMANDS = new Set(['ls', 'pwd', 'date']);
  
  const restrictedTool = new DynamicTool({
    name: 'restricted_shell',
    description: 'Execute only: ls, pwd, date',
    func: async (command: string) => {
      const baseCmd = command.split(' ')[0];
      // GOOD: Whitelist validation
      if (!ALLOWED_COMMANDS.has(baseCmd)) {
        return 'Command not allowed';
      }
      return new Promise((resolve) => {
        exec(command, (_, stdout) => resolve(stdout || ''));
      });
    }
  });
  
  const agent = await createOpenAIFunctionsAgent({
    llm,
    tools: [restrictedTool],
    prompt: PromptTemplate.fromTemplate('{input}')
  });
  
  return new AgentExecutor({ agent, tools: [restrictedTool], maxIterations: 3 });
}

export {
  vulnerableDirectInput,
  vulnerableTemplateLiteral,
  vulnerableApiKeyExposure,
  vulnerablePiiExposure,
  vulnerableEvalOutput,
  vulnerableShellExecution,
  vulnerableHtmlInjection,
  vulnerableShellTool,
  vulnerableFileSystemTool,
  VulnerableMCPServer,
  safeInputHandling,
  safeRestrictedShell
};
