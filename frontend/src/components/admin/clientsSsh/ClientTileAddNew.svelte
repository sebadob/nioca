<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import * as yup from "yup";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import {onMount} from "svelte";
    import Button from "$lib/Button.svelte";
    import {
        REGEX_CLIENT_NAME, SSH_CERT_TYPES,
    } from "../../../utils/constants.js";
    import IconClipboard from "$lib/icons/IconClipboard.svelte";
    import {fetchPostClientsSsh} from "../../../utils/dataFetching.js";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import Input from "$lib/inputs/Input.svelte";

    export let groups = [];
    export let onSave;

    let client = {name: ''}
    let expandContainer;

    let err = '';
    let isInitialized = false;
    let isLoading = false;
    let success = false;
    let uuid = '';
    let timer;

    let formErrors = {};
    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CLIENT_NAME, "Can only contain characters, numbers and '-_. '"),
    });

    function groupIdByName(name) {
        for (let g of groups) {
            if (g.name === name) {
                return g.id;
            }
        }
    }

    let groupName = 'default';
    $: groupOptions = groups.map(g => g.name);

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            onSave();
        }, 1500);
    }

    $: if (groups?.length > 0) {
        isInitialized = true;
    }

    onMount(() => {
        return () => {
            client = {name: ''};
            uuid = '';
            clearTimeout(timer);
        }
    });

    function copy() {
        navigator.clipboard.writeText(uuid);
    }

    async function onSubmit() {
        err = '';
        isLoading = true;

        const valid = await validateForm();
        if (!valid) {
            err = 'Invalid input';
            return;
        }

        client.enabled = true;
        client.keyAlg = 'ED25519';
        client.groupId = groupIdByName(groupName);

        client.validSecs = 3600;

        if (client.typ === 'User') {
            client.principals = ['nobody'];
            client.permitX11Forwarding = false;
            client.permitAgentForwarding = false;
            client.permitPortForwarding = true;
            client.permitPty = true;
            client.permitUserRc = true;
        } else {
            client.principals = ['localhost'];
        }

        let res = await fetchPostClientsSsh(client);
        let body = await res.json();
        if (res.ok) {
            success = true;
            uuid = body.id;
            client = {name: ''};
            expandContainer = false;
            onSave();
        } else {
            err = body.message;
        }

        isLoading = false;
    }

    async function validateForm() {
        try {
            await schema.validate(client, {abortEarly: false});
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <div class="data">
            Add New Client
        </div>
    </div>

    <div slot="body">
        {#if !isInitialized}
            <div class="notInitialized">
                Before you can add any SSH client, you must initialize at least the default SSH CA.
            </div>
        {:else}
            <!-- Client Name -->
            <div class="data">
                <Input
                        name="clientName"
                        bind:value={client.name}
                        bind:error={formErrors.name}
                        placeholder="Client Name"
                        on:blur={validateForm}
                >
                    NAME
                </Input>
            </div>

            <!-- Cert Type -->
            <div class="data ml">
                <div class="flex">
                    <div class="label">
                        Type
                    </div>
                    <OptionSelect
                            options={SSH_CERT_TYPES}
                            bind:value={client.typ}
                    />
                </div>
            </div>

            <!-- Group -->
            <div class="data ml">
                <div class="flex">
                    <div class="label">
                        Group
                    </div>
                    <OptionSelect
                            options={groupOptions}
                            bind:value={groupName}
                    />
                </div>
            </div>

            <!-- Save Button-->
            <div class="data">
                <Button on:click={onSubmit}>SAVE</Button>

                {#if success}
                    <div class="success">
                        Success
                    </div>
                {/if}

                {#if err}
                    <div class="mainErr err">
                        {err}
                    </div>
                {/if}
            </div>

            <!-- Final UUID-->
            {#if uuid}
                <div class="final">
                    <div class="flexRow">
                        The UUID of the new client:
                    </div>
                    <div class="flexRow">
                        {uuid}
                        <div
                                class="btn"
                                on:click={copy}
                                on:keypress={copy}
                        >
                            <IconClipboard/>
                        </div>
                    </div>
                </div>
            {/if}
        {/if}

        <div style="height: 7px"></div>
    </div>
</ExpandContainer>

<style>
    .btn {
        margin-left: 10px;
        opacity: 0.85;
        cursor: pointer;
    }

    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .header {
        display: flex;
    }

    .err {
        color: var(--col-err);
    }

    .final {
        display: flex;
        flex-direction: column;
        margin: 10px;
    }

    .flex {
        display: flex;
        align-items: center;
    }

    .flexRow {
        display: flex;
        margin: 5px 0;
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .ml {
        margin-left: 15px;
    }

    .notInitialized {
        margin: 10px;
    }

    .success {
        color: var(--col-ok);
    }

    .label {
        min-height: 30px;
        width: 8rem;
        margin-right: 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }
</style>
