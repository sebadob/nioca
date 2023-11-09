<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import * as yup from "yup";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import {onMount} from "svelte";
    import Button from "$lib/Button.svelte";
    import {
        REGEX_CLIENT_NAME,
    } from "../../../utils/constants.js";
    import IconClipboard from "$lib/icons/IconClipboard.svelte";
    import {fetchPostClientsX509} from "../../../utils/dataFetching.js";
    import Input from "$lib/inputs/Input.svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";

    export let groups = [];

    export let onSave;

    let isLoading = false;
    let client = {name: ''};
    let expandContainer;

    let err = '';
    let success = false;
    let uuid = '';
    let timer;

    function groupIdByName(name) {
        for (let g of groups) {
            if (g.name === name) {
                return g.id;
            }
        }
    }

    let groupName = 'default';
    $: groupOptions = groups.map(g => g.name);

    let formErrors = {};
    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CLIENT_NAME, "Can only contain characters, numbers and '-_. '"),
    });

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            onSave();
        }, 1500);
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
        client.groupId = groupIdByName(groupName);
        client.keyAlg = 'EdDSA';
        client.commonName = 'host.example.com';
        client.altNamesDns = [];
        client.altNamesIp = [];
        client.keyUsage = [];
        client.keyUsageExt = ['ClientAuth', 'ServerAuth'];
        client.validHours = 72;
        client.email = 'change@me.org';

        let res = await fetchPostClientsX509(client);
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
                            role="button"
                            tabindex="0"
                            class="btn"
                            on:click={copy}
                            on:keypress={copy}
                    >
                        <IconClipboard/>
                    </div>
                </div>
            </div>
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

    .success {
        color: var(--col-ok);
    }
</style>
