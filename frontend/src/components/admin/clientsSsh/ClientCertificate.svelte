<script>
    import Button from "$lib/Button.svelte";
    import {fetchGetClientSshSecret, fetchSshCert} from "../../../utils/dataFetching.js";
    import HiddenValueArea from "../../HiddenValueArea.svelte";

    export let client;

    const areaWidth = '40rem';

    let err = '';
    let secret = '';
    let isLoading = false;

    let cert;
    let caPubKey;

    async function fetchSecret() {
        let res = await fetchGetClientSshSecret(client.id);
        let body = await res.json();
        if (!res.ok) {
            err = body.message;
        } else {
            return body.secret;
        }
    }

    async function onSubmit() {
        err = '';
        isLoading = true;

        let secret = await fetchSecret();
        if (!secret) {
            return;
        }

        let res = await fetchSshCert(client.id, secret);
        let body = await res.json();
        console.log(body);
        if (res.ok) {
            console.log(body);
            cert = body.hostKeyPair;
            caPubKey = body.userCaPub;
        } else {
            err = body.message;
        }

        isLoading = false;
    }

</script>

<div class="data">
    <div class="label">
        Generate a new client SSH certificate?
    </div>

    <div class="value">
        <div class="btn">
            <Button on:click={onSubmit} bind:isLoading>GENERATE</Button>
        </div>

        {#if err}
            <div class="err">
                {err}
            </div>
        {/if}
    </div>

    {#if cert}
        <div class="row">
            <div class="certLabel">
                Type
            </div>
            <div class="certValue">
                {cert.typ}
            </div>
        </div>

        <div class="row">
            <div class="certLabel">
                Algorithm
            </div>
            <div class="certValue">
                {cert.alg}
            </div>
        </div>

        <div class="certBlock">
            <div class="certLabel">
                Certificate
            </div>
            <HiddenValueArea
                    name="id_pub"
                    rows={10}
                    value={cert.id_pub}
                    show
                    width={areaWidth}
            />
        </div>

        <div class="certBlock">
            <div class="certLabel">
                Private Key
            </div>
            <HiddenValueArea
                    name="id"
                    rows={10}
                    value={cert.id}
                    canHide
                    width={areaWidth}
            />
        </div>

        <div class="certBlock">
            <div class="certLabel">
                CA Public Key
            </div>
            <HiddenValueArea
                    name="id"
                    rows={2}
                    value={caPubKey}
                    show
                    width={areaWidth}
            />
        </div>
    {/if}
</div>

<style>
    .btn {
        width: 7rem;
    }

    .certBlock {
        margin: 5px 0;
        display: flex;
        flex-direction: column;
    }

    .certLabel {
        width: 100px;
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

    .row {
        display: flex;
        align-items: center;
        width: 500px;
    }

    .value {
        margin: 5px 0 25px 0;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
</style>
