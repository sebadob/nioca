<script>
    import {fetchExternalCASshRoot, fetchGenerateCASshRoot} from "../../../utils/dataFetching.js";
    import Button from "$lib/Button.svelte";
    import {scale} from 'svelte/transition';
    import OptionSelect from "$lib/OptionSelect.svelte";
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import * as yup from "yup";
    import {REGEX_KEY_HEX, SSH_CERT_AGLS} from "../../../utils/constants.js";
    import {extractFormErrors} from "../../../utils/helpers.js";

    const btnWidth = 150;

    export let cas;

    let alg = 'ED25519';
    let err = '';
    let isLoading = false;
    let showExternal = false;
    let showGenerate = false;
    let keyEncHex = '';

    let formValues = {};
    let formErrors = {};

    const schema = yup.object().shape({
        keyEncHex: yup.string().trim().matches(REGEX_KEY_HEX, 'Must be a valid HEX format'),
        keyPassword: yup.string().required('Required').max(1024, 'Maximum length: 1024 characters'),
    });

    async function autoGenerate() {
        let data = {
            alg,
        }

        isLoading = true;

        let res = await fetchGenerateCASshRoot(data);
        let body = await res.json();
        if (res.ok) {
            cas = {
                casSsh: [body],
            };
        } else {
            err = body.message;
        }

        isLoading = false;
    }

    async function addExternal() {
        err = '';

        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
        } catch (err) {
            formErrors = extractFormErrors(err);
            return;
        }

        isLoading = true;

        const data = {
            keyEncHex: formValues.keyEncHex,
            password: formValues.keyPassword,
        };
        console.log(data);

        let res = await fetchExternalCASshRoot(data);
        let body = await res.json();
        if (res.ok) {
            cas = {
                casSsh: [body],
            };
        } else {
            err = body.message;
        }

        isLoading = false;
    }

</script>

<div class="notInitialized">
    <p>
        The default SSH Certificate Authority has not been initialized yet.
    </p>
    <p>
        You have 2 options for the initialization: Either auto-generate a CA or add an external one.<br>
        The external one can be generated the same way as the X509 CA on an offline host. It has the advantage (and
        security risk at the same time), that you can generate valid SSH certificates in case Nioca is locked down
        and cannot be accessed for some reason, which might lock you out of your hosts, depending on the specific
        <code>sshd_config</code>.
    </p>
    <p>
        <span class="caution">CAUTION:</span> The SSH CA can only be initialized once!
    </p>

    <div class="btn" transition:scale|global>
        {#if !showExternal}
            <Button on:click={() => showGenerate = !showGenerate} bind:isLoading width={btnWidth}>
                AUTO-GENERATE
            </Button>
        {/if}

        {#if !showGenerate}
            <Button on:click={() => showExternal = !showExternal} bind:isLoading width={btnWidth}>
                EXTERNAL
            </Button>
        {/if}
    </div>

    {#if showGenerate}
        <div class="exec" transition:scale|global="{{ delay: 1 }}">
            Key Algorithm:
            <OptionSelect
                    options={SSH_CERT_AGLS}
                    bind:value={alg}
            />
            <div class="btn">
                <Button on:click={autoGenerate} bind:isLoading width={btnWidth}>
                    EXECUTE
                </Button>
            </div>
        </div>
    {/if}

    {#if showExternal}
        <div class="exec" transition:scale|global="{{ delay: 1 }}">
            <div class="block">
                <div class="desc">
                    Encrypted Private Key from <code>nioca ssh -s root</code><br>
                    Default folder: <code>./ca/ssh/root/key.enc.hex</code>
                </div>

                <div class="formRow" style="width: 480px;">
          <textarea
                  name="keyEncHex"
                  class="font-mono"
                  placeholder="Encrypted private Key in HEX format"
                  rows={15}
                  cols={20}
                  bind:value={formValues.keyEncHex}
          ></textarea>
                </div>

                {#if formErrors.keyEncHex}
          <span class="err">
            {formErrors.keyEncHex}
          </span>
                {/if}
            </div>

            <div class="block">
                <div class="desc">
                    Key encryption password:
                </div>
                <div class="formRow">
                    <div class="inputRow">
                        <PasswordInput
                                name="keyPassword"
                                placeholder="Encryption Password"
                                width={480}
                                showClip={false}
                                bind:value={formValues.keyPassword}
                        />
                    </div>

                    {#if formErrors.keyPassword}
            <span class="err">
              {formErrors.keyPassword}
            </span>
                    {/if}
                </div>
            </div>

            <div class="btn">
                <Button on:click={addExternal} bind:isLoading width={btnWidth}>
                    Save
                </Button>
            </div>
        </div>
    {/if}

    <div class="err">
        {err}
    </div>
</div>

<style>
    .block {
        margin: 20px 0;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }

    .btn {
        margin: 10px;
    }

    .caution {
        font-weight: bold;
        color: var(--col-err);
    }

    .desc {
        width: 480px;
        text-align: left;
    }

    .err {
        color: var(--col-err);;
    }

    .formRow {
        display: flex;
        flex-direction: column;
        flex: 1;
        text-align: right;
    }

    .notInitialized {
    }

    textarea {
        resize: none;
        border: 1px solid var(--col-gmid);
        border-radius: 3px;
        outline: none;
    }

    textarea:focus {
        resize: none;
        border: 1px solid var(--col-acnt);
    }
</style>
