<script>
    import * as yup from "yup";
    import {extractFormErrors, getKey} from "../../../utils/helpers.js";
    import Switch from "$lib/Switch.svelte";
    import Button from "$lib/Button.svelte";
    import {onMount} from "svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import ExpandableFormInputs from "../../ExpandableFormInputs/ExpandableFormInputs.svelte";
    import {
        REGEX_CLIENT_NAME, REGEX_DNS_SIMPLE, REGEX_LINUX_USER, SSH_CERT_AGLS, SSH_CERT_TYPES,
    } from "../../../utils/constants.js";
    import {fetchPutClientSsh} from "../../../utils/dataFetching.js";
    import Input from "$lib/inputs/Input.svelte";
    import ExpandableInputs from "$lib/expandableInputs/ExpandableInputs.svelte";

    export let client = {
        principals: ['nobody'],
    };
    export let groups = [];
    export let onSave;

    const urlInputWidth = '350px';

    let isLoading = false;
    let err = '';
    let success = false;
    let timer;

    function groupIdByName(name) {
        for (let g of groups) {
            if (g.name === name) {
                return g.id;
            }
        }
    }

    function groupNameById(id) {
        for (let g of groups) {
            if (g.id === id) {
                return g.name;
            }
        }
    }

    let groupName = groupNameById(client.groupId);
    $: groupOptions = groups.map(g => g.name);

    // callback function from ExpandableFormInputs
    let validatePrincipals;
    let principals = client.principals?.map(p => {
        return {
            name: getKey(),
            value: p,
        }
    });

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            onSave();
        }, 3000);
    }

    onMount(() => {
        return () => clearTimeout(timer);
    });

    let formErrors = {};

    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CLIENT_NAME, "Can only contain characters, numbers and '-_. '"),
        validSecs: yup.number().required('Required').min(1, 'Cannot be lower than 1').max(31536000, 'Cannot be higher than 2147483647'),
    });

    function handleKeyPress(event) {
        if (event.code === 'Enter') {
            onSubmit();
        }
    }

    async function onSubmit() {
        err = '';
        isLoading = true;

        const valid = await validateForm();
        if (!valid || !validatePrincipals()) {
            err = 'Invalid input';
            return;
        }

        let data = client;
        data.groupId = groupIdByName(groupName);
        data.principals = client.principals.filter(p => p.length > 0);
        data.validSecs = Number.parseInt(data.validSecs);

        let res = await fetchPutClientSsh(client.id, client);
        let body = await res.json();
        if (res.ok) {
            client = body;
            success = true;
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

<!-- Client ID -->
<div class="data ml">
    <div class="label">
        ID
    </div>
    <div class="clientId font-mono">
        {client.id}
    </div>
</div>

<!-- Client Name -->
<div class="data">
    <Input
            name="clientName"
            bind:value={client.name}
            bind:error={formErrors.name}
            placeholder="Client Name"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        CLIENT NAME
    </Input>
</div>

<!-- Client Enabled -->
<div class="data ml" style="margin-bottom: 10px">
    <div class="label font-label">
        Enabled
    </div>
    <div class="value">
        <Switch bind:selected={client.enabled}/>
    </div>
</div>

<!-- Cert Valid Secs -->
<div class="data">
    <Input
            name="validSecs"
            bind:value={client.validSecs}
            bind:error={formErrors.validSecs}
            placeholder="Valid for Seconds"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        VALID FOR SECONDS
    </Input>
</div>

<!-- Group -->
<div class="data ml">
    <div class="label">
        Group
    </div>
    <OptionSelect
            options={groupOptions}
            bind:value={groupName}
    />
</div>

<!-- Key Alg -->
<div class="data ml">
    <div class="label">
        Key Algorithm
    </div>
    <OptionSelect
            options={SSH_CERT_AGLS}
            bind:value={client.keyAlg}
    />
</div>

<div class="separator">
</div>

<!-- Principals -->
<div class="desc">
    Principals for <code>Host</code> Cert Types are hostnames.<br>
    For <code>User</code> Cert Types they must match usernames on the target system.<br>
</div>
<div class="data ml">
    <ExpandableInputs
            validation={{
                required: false,
                regex: REGEX_LINUX_USER,
                errMsg: "Valid characters: [a-z0-9-_@.]{2,30}",
            }}
            bind:values={client.principals}
            bind:validate={validatePrincipals}
            autocomplete="off"
            placeholder="Valid Principal"
            width={urlInputWidth}
    >
        VALID PRINCIPALS
    </ExpandableInputs>
</div>

<div class="separator">
</div>

<!-- Key Alg -->
<div class="data ml">
    <div class="label">
        Cert Type
    </div>
    <OptionSelect
            options={SSH_CERT_TYPES}
            bind:value={client.typ}
    />
</div>

{#if client.typ === 'User'}
    <div class="data">
        <div class="flex">
            <div class="label switchLabel">
                X11 Forwarding
            </div>
            <div class="value">
                <Switch bind:selected={client.permitX11Forwarding}/>
            </div>
        </div>
    </div>

    <div class="data">
        <div class="flex">
            <div class="label switchLabel">
                Agent Forwarding
            </div>
            <div class="value">
                <Switch bind:selected={client.permitAgentForwarding}/>
            </div>
        </div>
    </div>

    <div class="data">
        <div class="flex">
            <div class="label switchLabel">
                Port Forwarding
            </div>
            <div class="value">
                <Switch bind:selected={client.permitPortForwarding}/>
            </div>
        </div>
    </div>

    <div class="data">
        <div class="flex">
            <div class="label switchLabel">
                PTY
            </div>
            <div class="value">
                <Switch bind:selected={client.permitPty}/>
            </div>
        </div>
    </div>

    <div class="data">
        <div class="flex">
            <div class="label switchLabel">
                User RC
            </div>
            <div class="value">
                <Switch bind:selected={client.permitUserRc}/>
            </div>
        </div>
    </div>
{/if}

<!-- Save Button-->
<div class="data">
    <div class="btn">
        <Button on:click={onSubmit}>Save</Button>
    </div>

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

<div style="height: 7px"></div>

<style>
    .btn {
        width: 10rem;
    }

    .clientId {
        margin: 5px;
    }

    .data {
        display: flex;
        flex-direction: column;
        margin: 3px 10px;
    }

    .desc {
        margin: 20px;
    }

    .err {
        color: var(--col-err);
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .ml {
        margin-left: 15px;
    }

    .flex {
        display: flex;
        align-items: center;
    }

    .switchLabel {
        width: 10rem;
    }

    .label {
        min-height: 30px;
        margin: 0 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }

    .separator {
        height: .5rem;
    }

    .success {
        color: var(--col-ok);
    }

    .value {
        margin-left: 5px;
        display: flex;
        align-items: center;
    }
</style>
