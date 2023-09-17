<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import * as yup from "yup";
    import {REGEX_CA_NAME, REGEX_KEY_HEX} from "../../../utils/constants.js";
    import Input from "$lib/inputs/Input.svelte";
    import Button from "$lib/Button.svelte";
    import Textarea from "$lib/inputs/Textarea.svelte";
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import {fetchPostCAX509} from "../../../utils/dataFetching.js";
    import {sleepAwait} from "$lib/utils/helpers.js";

    export let onSave;

    const inputWidth = '31.5rem';

    let isLoading = false;
    let err = '';
    let success = false;
    let expandContainer;

    let formErrors = {};
    let formValues = {};
    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CA_NAME, 'Invalid Name'),
        rootPem: yup.string().required('Required').max(5000, 'Maximum length: 5000 characters'),
        intermediatePem: yup.string().required('Required').max(5000, 'Maximum length: 5000 characters'),
        intermediateKeyHex: yup.string().trim().matches(REGEX_KEY_HEX, 'Must be a valid HEX format'),
        keyPassword: yup.string().required('Required').max(1024, 'Maximum length: 1024 characters'),
    });

    async function onSubmit() {
        err = '';
        isLoading = true;

        const valid = await validateForm();
        if (!valid) {
            err = 'Invalid input';
            return;
        }

        const data = {
            name: formValues.name,
            rootPem: formValues.rootPem,
            itPem: formValues.intermediatePem,
            itKey: formValues.intermediateKeyHex,
            itPassword: formValues.keyPassword,
        };

        let res = await fetchPostCAX509(data);
        if (res.ok) {
            success = true;
            await sleepAwait(2000);
            expandContainer = false;
            onSave();
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function validateForm() {
        err = '';

        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
            return additionalValidation();
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

    function additionalValidation() {
        if (!formValues.rootPem.includes('-----BEGIN CERTIFICATE-----')
            || !formValues.rootPem.includes('-----END CERTIFICATE-----')) {
            formErrors.rootPem = 'Must be a valid PEM format';
            return false;
        }

        if (!formValues.intermediatePem.includes('-----BEGIN CERTIFICATE-----')
            || !formValues.intermediatePem.includes('-----END CERTIFICATE-----')) {
            formErrors.intermediatePem = 'Must be a valid PEM format';
            return false;
        }

        return true;
    }

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <div class="data font-mono">
            Add New CA
        </div>
    </div>

    <div slot="body">
        <!-- Client Name -->
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

        <!-- Root Cert PEM -->
        <div class="data">
            <Textarea
                    rows=17
                    name="rootPem"
                    placeholder="Root Certificate in PEM format"
                    bind:value={formValues.rootPem}
                    bind:error={formErrors.rootPem}
            >
                Root Certificate in PEM format
            </Textarea>
        </div>

        <!-- Intermediate Cert PEM -->
        <div class="data">
            <Textarea
                    rows=17
                    name="intermediatePem"
                    placeholder="Intermediate Certificate in PEM format"
                    bind:value={formValues.intermediatePem}
                    bind:error={formErrors.intermediatePem}
            >
                Intermediate Certificate in PEM format
            </Textarea>
        </div>
        <div class="data">
            <Textarea
                    rows=12
                    name="intermediateKeyHex"
                    placeholder="Intermediate Key in encrypted PEM-HEX format"
                    bind:value={formValues.intermediateKeyHex}
                    bind:error={formErrors.intermediateKeyHex}
            >
                Intermediate Key in encrypted PEM-HEX format
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
            <Button on:click={onSubmit} bind:isLoading>SAVE</Button>

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

    .header {
        display: flex;
        align-items: center;
    }

    .success {
        color: var(--col-ok);
    }
</style>
