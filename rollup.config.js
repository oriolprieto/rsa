import typescript from '@rollup/plugin-typescript';

export default{
    input: 'src/rsa.js',
    output: [
        {
            file: 'rsa.cjs.js',
            format: 'cjs'
        },
        {
            file: 'rsa.esm.js',
            format: 'esm'
        }
    ],
    //external: ['bigint-crypto-utils']
    external: ['bigint-crypto-utils','bigint-conversion']
};
