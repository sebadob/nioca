<script>
    import * as yup from "yup";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import Switch from "$lib/Switch.svelte";
    import Button from "$lib/Button.svelte";
    import {onMount} from "svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import SwitchList from "$lib/SwitchList.svelte";
    import {
        OPT_X509_KEY_ALG,
        REGEX_CLIENT_NAME, REGEX_COMMON_NAME, REGEX_COMMON_NAME_OPT,
        REGEX_DNS_SIMPLE, REGEX_EMAIL,
        REGEX_IP_V4,
        X509_KEY_USAGES, X509_KEY_USAGES_EXT
    } from "../../../utils/constants.js";
    import {fetchPutClientX509} from "../../../utils/dataFetching.js";
    import Input from "$lib/inputs/Input.svelte";
    import ExpandableInputs from "$lib/expandableInputs/ExpandableInputs.svelte";

    export let groups = [];
    export let client = {};
    export let onSave;

    const urlInputWidth = '23.5rem';

    let isLoading = false;
    let err = '';
    let success = false;
    let timer;

    // let altNamesDns = client.altNamesDns?.map(origin => {
    //     return {
    //         name: getKey(),
    //         value: origin,
    //     }
    // });
    // will bind to the validation function inside the ExpandableFormInputs component
    let validateAltNamesDns;

    // let altNamesIp = client.altNamesIp?.map(uri => {
    //     return {
    //         name: getKey(),
    //         value: uri,
    //     }
    // });
    // will bind to the validation function inside the ExpandableFormInputs component
    let validateAltNamesIp;

    let keyUsages = X509_KEY_USAGES.map(f => {
        f.value = client.keyUsage?.includes(f.label);
        return f;
    });

    let keyUsagesExt = X509_KEY_USAGES_EXT.map(f => {
        f.value = client.keyUsageExt?.includes(f.label);
        return f;
    });

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
        name: yup.string().required('Required').trim().matches(REGEX_CLIENT_NAME, "Can only contain characters, numbers and '-_. '"),
        email: yup.string().trim().matches(REGEX_EMAIL, "Valid E-Mail address"), // TODO implement
        validHours: yup.number().required('Required').min(1, 'Cannot be lower than 1').max(175200, 'Cannot be higher than 175200'),
        commonName: yup.string().required('Required').matches(REGEX_COMMON_NAME, "Can only contain characters, numbers and '.*-'"),
        country: yup.string().nullable().matches(REGEX_COMMON_NAME_OPT, "Can only contain characters, numbers and '.*- '"),
        locality: yup.string().nullable().matches(REGEX_COMMON_NAME_OPT, "Can only contain characters, numbers and '.*- '"),
        organizationalUnit: yup.string().nullable().matches(REGEX_COMMON_NAME_OPT, "Can only contain characters, numbers and '.*- '"),
        organization: yup.string().nullable().matches(REGEX_COMMON_NAME_OPT, "Can only contain characters, numbers and '.*- '"),
        stateOrProvince: yup.string().nullable().matches(REGEX_COMMON_NAME_OPT, "Can only contain characters, numbers and '.*- '"),
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
        if (!valid || !validateAltNamesDns() || !validateAltNamesIp()) {
            err = 'Invalid input';
            return;
        }

        let data = client;

        data.groupId = groupIdByName(groupName);
        data.validHours = Number.parseInt(client.validHours);
        data.country = client.country?.length > 0 ? client.country : null;
        data.locality = client.locality?.length > 0 ? client.locality : null;
        data.organization = client.organization?.length > 0 ? client.organization : null;
        data.organizationalUnit = client.organizationalUnit?.length > 0 ? client.organizationalUnit : null;
        data.stateOrProvince = client.stateOrProvince?.length > 0 ? client.stateOrProvince : null;

        data.altNamesDns = client.altNamesDns.filter(r => r.length > 0);
        data.altNamesIp = client.altNamesIp.filter(r => r.length > 0);

        data.keyUsage = keyUsages.filter(f => f.value).map(f => f.label);
        data.keyUsageExt = keyUsagesExt.filter(f => f.value).map(f => f.label);

        let res = await fetchPutClientX509(client.id, data);
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
<div class="data">
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
        NAME
    </Input>
</div>

<!-- Client Enabled -->
<div class="data" style="margin-bottom: 10px">
    <div class="label">
        Enabled
    </div>
    <div class="value">
        <Switch bind:selected={client.enabled}/>
    </div>
</div>

<!-- E-Mail -->
<div class="data">
    <Input
            name="email"
            bind:value={client.email}
            bind:error={formErrors.email}
            placeholder="Contact E-Mail"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        E-MAIL
    </Input>
</div>

<!-- Cert Valid Hours -->
<div class="data">
    <Input
            name="validHours"
            bind:value={client.validHours}
            bind:error={formErrors.validHours}
            placeholder="Certificate validity in hours"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        VALID FOR HOURS
    </Input>
</div>

<!--TODO: create option selector for all groups-->
<!-- Group Selector -->
<div class="data">
    <div class="label">
        Group
    </div>
    <OptionSelect bind:value={groupName} options={groupOptions}/>
</div>

<!-- X509 Subject -->
<div class="separator" style="margin-top: 15px; margin-bottom: 10px">
</div>
<div class="desc">
    The X509 certificate subject section
</div>

<!-- Common Name -->
<div class="data">
    <Input
            name="commonName"
            bind:value={client.commonName}
            bind:error={formErrors.commonName}
            placeholder="Common Name"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        COMMON NAME
    </Input>
</div>

<!-- Country -->
<div class="data">
    <Input
            name="country"
            bind:value={client.country}
            bind:error={formErrors.country}
            placeholder="Country"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        COUTNRY
    </Input>
</div>

<!-- Locality -->
<div class="data">
    <Input
            name="locality"
            bind:value={client.locality}
            bind:error={formErrors.locality}
            placeholder="Locality"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        LOCALITY
    </Input>
</div>

<!-- Organizational Unit -->
<div class="data">
    <Input
            name="organizationalUnit"
            bind:value={client.organizationalUnit}
            bind:error={formErrors.organizationalUnit}
            placeholder="Organizational Unit"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        ORGANISATIONAL UNIT
    </Input>
</div>

<!-- Organization -->
<div class="data">
    <Input
            name="organization"
            bind:value={client.organization}
            bind:error={formErrors.organization}
            placeholder="Organization"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        ORGANISATION
    </Input>
</div>

<!-- State or Province -->
<div class="data">
    <Input
            name="stateOrProvince"
            bind:value={client.stateOrProvince}
            bind:error={formErrors.stateOrProvince}
            placeholder="State or Province"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
    >
        STATE OR PROVINCE
    </Input>
</div>

<!-- Alt Names -->
<div class="separator" style="margin-top: 20px; margin-bottom: 5px">
</div>
<div class="desc">
    Alternative names which are valid in addition to the Common Name
</div>

<!-- Alt Names DNS -->
<div class="data">
    <ExpandableInputs
            validation={{
                required: false,
                regex: REGEX_DNS_SIMPLE,
                errMsg: "Only valid DNS Name values: [a-zA-Z0-9.-*]",
            }}
            bind:values={client.altNamesDns}
            bind:validate={validateAltNamesDns}
            autocomplete="off"
            optional
            placeholder="Alternative Name DNS"
            width={urlInputWidth}
    >
        ALTERNATIVE NAME DNS
    </ExpandableInputs>
</div>

<!-- Alt Names IP -->
<div class="data">
    <ExpandableInputs
            validation={{
                required: false,
                regex: REGEX_IP_V4,
                errMsg: "Only valid IP v4 addresses",
            }}
            bind:values={client.altNamesIp}
            bind:validate={validateAltNamesIp}
            autocomplete="off"
            optional
            placeholder="Alternative Name IP"
            width={urlInputWidth}
    >
        ALTERNATIVE NAME IP
    </ExpandableInputs>
</div>

<!-- Key Alg and Usage -->
<div class="separator" style="margin-top: 20px; margin-bottom: 15px">
</div>
<div class="desc">
    Key algorithm and usages
</div>

<!-- Key Alg -->
<div class="data">
    <div class="label">
        Key Algorithm
    </div>
    <OptionSelect bind:value={client.keyAlg} options={OPT_X509_KEY_ALG}/>
</div>

<!-- Key Usages -->
<div class="data">
    <div class="label">
        X509 Key Usages
    </div>
    <div class="value">
        <SwitchList bind:options={keyUsages} labelWidth="10rem"/>
    </div>
</div>

<!-- Key Usages Ext -->
<div class="data">
    <div class="label">
        X509 Key Usages Extended
    </div>
    <div class="value">
        <SwitchList bind:options={keyUsagesExt} labelWidth="10rem"/>
    </div>
</div>

<div class="separator" style="margin-top: 15px; margin-bottom: 5px">
</div>

<!-- Save Button-->
<div class="data">
    <div class="btn">
        <Button on:click={onSubmit}>SAVE</Button>
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
        margin: 10px 15px;
    }

    .err {
        color: var(--col-err);
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .label {
        min-height: 30px;
        margin: 0 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }

    .separator {
        margin: 0 10px;
        border-bottom: 1px solid var(--col-inact);
    }

    .success {
        color: var(--col-ok);
    }

    .value {
        margin-left: 5px;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
    }
</style>
