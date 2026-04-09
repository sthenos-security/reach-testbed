// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: react_jsx_auto_escape
// SOURCE: props (user-provided)
// SINK: JSX text content (auto-escaped)
// TAINT_HOPS: 1
// NOTES: React JSX auto-escapes text content
import React from 'react';

interface Props {
  userContent: string;
}

// SAFE: React JSX auto-escapes text content in curly braces
export const SafeComponent: React.FC<Props> = ({ userContent }) => {
  return <div>{userContent}</div>;
};
