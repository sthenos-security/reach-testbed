// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: react_dangerously_set_inner_html
// SOURCE: props (user-provided)
// SINK: dangerouslySetInnerHTML
// TAINT_HOPS: 1
import React from 'react';

interface Props {
  userContent: string;
}

// VULNERABLE: CWE-79 · dangerouslySetInnerHTML with user content
export const UnsafeComponent: React.FC<Props> = ({ userContent }) => {
  return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
};
