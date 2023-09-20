<script>
    import Button from "$lib/Button.svelte";
    import {fetchGetClientX509Secret, fetchPEM, fetchPKCS12} from "../../../utils/dataFetching.js";
    import {downloadBlob} from "../../../utils/helpers.js";
    import HiddenValueArea from "../../HiddenValueArea.svelte";

    const areaWidth = '38rem';

    export let client;

    let err = '';
    let isLoading = false;
    let pem;

    async function fetchSecret() {
        let res = await fetchGetClientX509Secret(client.id);

        let body = await res.json();
        if (!res.ok) {
            err = body.message;
        } else {
            return body.secret;
        }
    }

    async function onSubmitP12() {
        err = '';
        isLoading = true;

        let secret = await fetchSecret();
        if (!secret) {
            return;
        }

        let res = await fetchPKCS12(client.id, secret);
        if (res.ok) {
            let blob = await res.blob();
            downloadBlob(blob);
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function onSubmitPEM() {
        err = '';
        isLoading = true;

        let secret = await fetchSecret();
        if (!secret) {
            return;
        }

        let res = await fetchPEM(client.id, secret);
        let body = await res.json();
        if (res.ok) {
            pem = body;
        } else {
            err = body.message;
        }

        isLoading = false;
    }

</script>

<div class="data">
    <div class="label">
        You can generate and download a new client X509 certificate in two formats:
    </div>
    <div class="value">
        <div class="btn">
            <Button on:click={onSubmitP12} bind:isLoading>PKCS12</Button>
            <Button on:click={onSubmitPEM} bind:isLoading>PEM</Button>
        </div>

        {#if err}
            <div class="err">
                {err}
            </div>
        {/if}
    </div>
</div>

{#if pem}
    <div class="data">
        <div class="certBlock">
            <div class="certLabel">
                PEM Certificate
            </div>
            <HiddenValueArea
                    name="id"
                    rows={17}
                    value={pem.cert}
                    show
                    width={areaWidth}
            />
        </div>

        <div class="certBlock">
            <div class="certLabel">
                Valid Until
            </div>
            <div>
                {new Date(pem.notAfter * 1000)}
            </div>
        </div>

        <div class="certBlock">
            <div class="certLabel">
                Fingerprint
            </div>
            <div>
                {pem.certFingerprint}
            </div>
        </div>

        <div class="certBlock">
            <div class="certLabel">
                PEM Key
            </div>
            <HiddenValueArea
                    name="id"
                    rows={7}
                    value={pem.key}
                    width={areaWidth}
            />
        </div>

        <div class="certBlock">
            <div class="certLabel">
                Full Certificate Chain
            </div>
            <HiddenValueArea
                    name="id"
                    rows={17}
                    value={pem.certChain}
                    show
                    width={areaWidth}
            />
        </div>
    </div>
{/if}

<style>
    .certBlock {
        margin: 5px 0;
        display: flex;
        flex-direction: column;
    }

    .certLabel {
        font-weight: bold;
    }

    .data {
        display: flex;
        flex-direction: column;
        margin: 3px 10px;
    }

    .err {
        display: flex;
        align-items: center;
        margin: 0 10px;
        color: var(--col-err);
    }

    .label {
        height: 30px;
        margin: 0 5px;
        display: flex;
        align-items: center;
        font-weight: bold;
    }

    .value {
        margin: 15px 0 25px 0;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
</style>
