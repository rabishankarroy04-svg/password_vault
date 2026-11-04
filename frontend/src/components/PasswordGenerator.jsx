import React,{useId,useState} from 'react';
import {generatePassword,assessPassword} from '../services/passwords';
export default function PasswordGenerator({onGenerate}){
 const id=useId();
 const [length,setLength]=useState(20),[options,setOptions]=useState({lowercase:true,uppercase:true,numbers:true,symbols:true}),[error,setError]=useState(''),[generated,setGenerated]=useState(false);
 return <fieldset className="password-generator"><legend>Generate a unique password</legend>
  <div className="generator-quick-row"><p>{length} characters · Browser cryptographic randomness</p><button type="button" onClick={()=>{try{onGenerate(generatePassword(length,options));setGenerated(true);setError('');}catch(e){setError(e.message);}}}><i className="fa-solid fa-arrows-rotate" aria-hidden="true"/> {generated?'Regenerate password':'Generate password'}</button></div>
  <details className="generator-options"><summary>Customize generator</summary><div><label htmlFor={id}>Password length<input id={id} aria-label="Password length" type="number" min={12} max={128} value={length} onChange={e=>setLength(Number(e.target.value))}/></label><div className="generator-character-options">{Object.keys(options).map(key=><label className="aurora-check" key={key}><input type="checkbox" checked={options[key]} onChange={e=>setOptions({...options,[key]:e.target.checked})}/>{key}</label>)}</div></div></details>
  <p className="generator-advice">Prefer at least 16 characters and a unique password for every account.</p>
  {error&&<p role="alert">{error}</p>}
 </fieldset>;
}
export function PasswordAssessment({password}){
 const result=assessPassword(password);
 return <div className="credential-strength" data-strength={result.strength} aria-live="polite"><strong>Password strength: {result.strength} ({result.score}/100)</strong><div className="credential-strength-track" role="meter" aria-label="Password strength" aria-valuemin={0} aria-valuemax={100} aria-valuenow={result.score} aria-valuetext={result.strength}><span style={{width:`${result.score}%`}}/></div><details><summary>Password guidance</summary><ul>{result.suggestions.map(text=><li key={text}>{text}</li>)}</ul></details></div>;
}
