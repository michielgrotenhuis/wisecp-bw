<?php if(!defined("CORE_FOLDER")) return false; ?>
<h3>Configuration with Form Elements</h3>
<a class="lbtn" href="<?php echo $area_link; ?>?module=<?php echo $m_name; ?>">Go to Back</a>
<form action="<?php echo $area_link; ?>" method="post" id="configurationForm">
    <input type="hidden" name="operation" value="module_controller">
    <input type="hidden" name="module" value="<?php echo $m_name; ?>">
    <input type="hidden" name="controller" value="save">

    <div class="formcon">
        <div class="yuzde30"><?php echo $lang["example1"]; ?></div>
        <div class="yuzde70">
            <input type="text" name="example1" value="<?php echo $config["settings"]["example1"]; ?>">
        </div>
    </div>

    <div class="formcon">
        <div class="yuzde30"><?php echo $lang["example2"]; ?></div>
        <div class="yuzde70">
            <input type="password" name="example2" value="<?php echo $config["settings"]["example2"]; ?>">
        </div>
    </div>

    <div class="formcon">
        <div class="yuzde30"><?php echo $lang["example3"]; ?></div>
        <div class="yuzde70">
            <input<?php echo $config["settings"]["example3"] ? ' checked' : ''; ?> type="checkbox" name="example3" value="1" id="example3" class="checkbox-custom">
            <label class="checkbox-custom-label" for="example3">
                <span class="kinfo"><?php echo $lang["example3-desc"]; ?></span>
            </label>
        </div>
    </div>


    <div class="clear"></div>
    <br>

    <div style="float:right;" class="guncellebtn yuzde30"><a id="configurationForm_submit" href="javascript:void(0);" class="yesilbtn gonderbtn"><?php echo ___("needs/button-save"); ?></a></div>
</form>
<script type="text/javascript">
    $(document).ready(function(){
        $("#configurationForm_submit").click(function(){
            MioAjaxElement($(this),{
                waiting_text:waiting_text,
                progress_text:progress_text,
                result:"configurationForm_handler",
            });
        });
    });
    function configurationForm_handler(result){
        if(result != ''){
            var solve = getJson(result);
            if(solve !== false){
                if(solve.status == "error"){
                    if(solve.message != undefined && solve.message != '')
                        alert_error(solve.message,{timer:5000});
                }else if(solve.status == "successful")
                    alert_success(solve.message,{timer:2500});
            }else
                console.log(result);
        }
    }
</script>
