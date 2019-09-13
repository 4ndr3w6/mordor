# Process Reimaging

Advesaries might attempt to reimage a malicious binary to defensively evade detection efforts. 

Example: Malicious binary is dropped on disk. Advesary will reimage it under the context of another non-malicious binary, allowing the Windows OS to return the wrong File Object. So when the file's `OriginalFileName` is looked at by the OS, it appears to be the non-malicious binary. 

## Technique Variations Table

| Sub-techinque | Author | Updated |
| ----------- | ------- | --------- | 
| [process_reimaging](process_reimaging.md) | Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101) | 2019-09-12174205 |