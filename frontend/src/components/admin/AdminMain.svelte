<script>
    import Nav from "./nav/Nav.svelte";
    import ContentWrapper from "./ContentWrapper.svelte";
    import {fetchLogout} from "../../utils/dataFetching.js";
    import {deleteXsrfToken} from "../../utils/helpers.js";
    import Config from "./config/Config.svelte";
    import TODO from "../TODO.svelte";
    import ClientsSsh from "./clientsSsh/ClientsSsh.svelte";
    import ClientsX509 from "./clientsX509/ClientsX509.svelte";
    import CaSsh from "./caSsh/CaSshMain.svelte";
    import CaX509 from "./caX509/CaX509Main.svelte";
    import Password from "./password/Password.svelte";
    import Groups from "./groups/Groups.svelte";

    let selected = 'X509';
    $: if (selected === 'Logout') {
        redirectToLogout();
    }

    async function redirectToLogout() {
        await fetchLogout();
        deleteXsrfToken();
        window.location.reload();
    }

</script>

<main>
    <Nav bind:selected/>

    {#if 'X509' === selected}
        <ContentWrapper>
            <ClientsX509/>
        </ContentWrapper>

    {:else if 'SSH' === selected}
        <ContentWrapper>
            <ClientsSsh/>
        </ContentWrapper>

    {:else if 'Groups' === selected}
        <ContentWrapper>
            <Groups/>
        </ContentWrapper>

    {:else if 'X509 CA' === selected}
        <ContentWrapper>
            <CaX509/>
        </ContentWrapper>

    {:else if 'SSH CA' === selected}
        <ContentWrapper>
            <CaSsh/>
        </ContentWrapper>

    {:else if 'Config' === selected}
        <ContentWrapper>
            <Config/>
        </ContentWrapper>

    {:else if 'Password' === selected}
        <ContentWrapper>
            <Password/>
        </ContentWrapper>

    {:else}
        <ContentWrapper>
            <TODO/>
        </ContentWrapper>
    {/if}
</main>

<style>
    main {
        width: 100vw;
        display: flex;
        align-items: center;
        flex-direction: row;
        overflow-y: auto;
        overflow-x: hidden;
    }
</style>
