<script>
    import NavEntry from "./NavEntry.svelte";
    import NavLogo from "./NavLogo.svelte";
    import IconOffice from "$lib/icons/IconOffice.svelte";
    import IconLogout from "$lib/icons/IconLogout.svelte";
    import {adminNavWidth} from "../../../stores/adminNav.js";
    import IconWrenchScrew from "$lib/icons/IconWrenchScrew.svelte";
    import NavSection from "./NavSection.svelte";
    import IconShieldCheck from "$lib/icons/IconShieldCheck.svelte";
    import {storePrincipal} from "../../../stores/principal.js";
    import IconKey from "../../icons/IconKey.svelte";
    import IconQueueList from "../../icons/IconQueueList.svelte";
    import IconUsers from "../../icons/IconUsers.svelte";

    export let selected = '';
    let colors = {};

    let principal;
    storePrincipal.subscribe(p => principal = p);

    let navWidth;
    adminNavWidth.subscribe(w => navWidth = `${w}px`);

</script>

<nav class="nav" style="width: {navWidth}">
    <div class="logo">
        <NavLogo/>
    </div>

    <div class="menu">
        <div class="links">

            <NavSection label="Clients">
                <div slot="logo">
                    <IconOffice/>
                </div>

                <div slot="entries">
                    <NavEntry bind:color={colors.client_tls} label="X509" bind:selected>
                    </NavEntry>

                    <NavEntry bind:color={colors.client_ssh} label="SSH" bind:selected>
                    </NavEntry>
                </div>
            </NavSection>

            <NavEntry bind:color={colors.groups} label="Groups" bind:selected>
                <IconQueueList color={colors.groups}/>
            </NavEntry>

            <NavSection label="Authorities">
                <div slot="logo">
                    <IconShieldCheck/>
                </div>

                <div slot="entries">
                    <NavEntry bind:color={colors.certs_tls} label="X509 CA" bind:selected>
                    </NavEntry>

                    <NavEntry bind:color={colors.certs_ssh} label="SSH CA" bind:selected>
                    </NavEntry>
                </div>
            </NavSection>

            <NavEntry bind:color={colors.users} label="Users" bind:selected>
                <IconUsers color={colors.users}/>
            </NavEntry>

            <NavEntry bind:color={colors.config} label="Config" bind:selected>
                <IconWrenchScrew color={colors.config}/>
            </NavEntry>

            {#if principal?.local && principal?.isAdmin}
                <NavEntry bind:color={colors.password} label="Password" bind:selected>
                    <IconKey color={colors.password}/>
                </NavEntry>
            {/if}
        </div>

        <div class="bottom">
            <NavEntry bind:color={colors.logout} label="Logout" bind:selected>
                <IconLogout color={colors.logout}/>
            </NavEntry>
        </div>
    </div>
</nav>

<style>
    .bottom {
        margin-bottom: 10px;
    }

    .menu {
        height: calc(100% - 20px);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }

    .links {
        flex: 1;
    }

    .nav {
        height: 100vh;
        padding: 20px;
        border-right: 1px solid var(--col-gmid);
        box-shadow: 3px 0 5px 5px var(--col-ghigh);
    }
</style>
