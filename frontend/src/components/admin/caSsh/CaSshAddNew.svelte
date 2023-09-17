<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import * as yup from "yup";
    import {REGEX_CA_NAME, REGEX_KEY_HEX, SSH_CERT_AGLS} from "../../../utils/constants.js";
    import Input from "$lib/inputs/Input.svelte";
    import {scale} from 'svelte/transition';
    import Button from "$lib/Button.svelte";
    import Textarea from "$lib/inputs/Textarea.svelte";
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import {fetchPostGenerateCASsh, fetchPostExternalCASsh} from '../../../utils/dataFetching.js';

    export let onSave;

    const btnWidth = '9rem';
    const inputWidth = '31.5rem';

    let alg = 'ED25519';
    let showExternal = false;
    let showGenerate = false;
    let isLoading = false;
    let err = '';
    let success = false;
    let show;

    let formErrors = {};
    let formValues = {};
    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CA_NAME, 'Invalid Name'),
    });

    const schemaExt = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CA_NAME, 'Invalid Name'),
        keyEncHex: yup.string().trim().matches(REGEX_KEY_HEX, 'Must be a valid HEX format'),
        keyPassword: yup.string().required('Required').max(1024, 'Maximum length: 1024 characters'),
    });

    async function autoGenerate() {
        let isValid = await validateForm();
        if (!isValid) {
            err = 'Invalid Input';
            return;
        }

        isLoading = true;

        let data = {
            name: formValues.name,
            alg,
        }

        let res = await fetchPostGenerateCASsh(data);
        if (res.ok) {
            onSuccess();
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function addExternal() {
        err = '';

        let isValid = await validateForm();
        if (!isValid) {
            err = 'Invalid Input';
            return;
        }

        isLoading = true;

        const data = {
            name: formValues.name,
            keyEncHex: formValues.keyEncHex,
            password: formValues.keyPassword,
        };

        let res = await fetchPostExternalCASsh(data);
        if (res.ok) {
            onSuccess();
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    function onSuccess() {
        showGenerate = false;
        showExternal = false;
        formValues = {};
        show = false;
        onSave();
    }

    async function validateForm() {
        err = '';

        try {
            await schema.validate(formValues, {abortEarly: false});
            if (showExternal) {
                await schemaExt.validate(formValues, {abortEarly: false});
            }
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

<ExpandContainer bind:show>
    <div class="header" slot="header">
        <div class="data font-mono">
            Add New CA
        </div>
    </div>

    <div slot="body">
        <!-- CA Name -->
        <div class="data">
            <Input
                    name="name"
                    bind:value={formValues.name}
                    bind:error={formErrors.name}
                    placeholder="CA Name"
                    width={inputWidth}
                    on:blur={validateForm}
            >
                CA NAME
            </Input>
        </div>

        <div class="data">
            <p>
                You have 2 options here: Either auto-generate a CA or add an external one.<br/><br/>
                The external one can be generated the same way as the X509 CA on an offline host. It has the advantage
                (and
                security risk at the same time), that you can generate valid SSH certificates in case Nioca is locked
                down
                and cannot be accessed for some reason, which might lock you out of your hosts, depending on the
                specific
                <code>sshd_config</code>.
            </p>
        </div>

        <div class="data" transition:scale|global>
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

        {#if showExternal}
            <!-- Encrypted Key -->
            <div class="data">
                <Textarea
                        rows=15
                        name="keyEncHex"
                        placeholder="Encrypted private Key in HEX format"
                        bind:value={formValues.keyEncHex}
                        bind:error={formErrors.keyEncHex}
                >
                    Encrypted private Key in HEX format
                </Textarea>
            </div>

            <!-- Intermediate Key encryption password -->
            <div class="data">
                <PasswordInput
                        name="keyPassword"
                        placeholder="Encryption Password"
                        width={inputWidth}
                        bind:value={formValues.keyPassword}
                        bind:error={formErrors.keyPassword}
                >
                    Intermediate Key encryption password
                </PasswordInput>
            </div>

            <!-- Save Button-->
            <div class="data">
                <Button on:click={addExternal} bind:isLoading>SAVE</Button>
            </div>
        {:else if showGenerate}
            <div class="data exec" transition:scale|global="{{ delay: 1 }}">
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

        <div class="data">
            {#if success}
                <div class="success">
                    Success
                </div>
            {/if}

            {#if err}
                <div class="err">
                    {err}
                </div>
            {/if}
        </div>

        <div style="height: 7px"></div>
    </div>
</ExpandContainer>

<style>
    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .err {
        color: var(--col-err);
    }

    .exec {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
    }

    .header {
        display: flex;
        align-items: center;
    }

    .success {
        color: var(--col-ok);
    }
</style>
