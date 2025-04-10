<?php if(!defined("CORE_FOLDER")) return false; ?>
<h3>Example List</h3>
<a class="lbtn" href="<?php echo $area_link; ?>?module=<?php echo $m_name; ?>">Go to Back</a>
<a class="lbtn green" href="javascript:void 0;"><i class="fa fa-plus"></i> Add</a>

<table width="100%" id="table_list">
    <thead>
    <tr>
        <th align="center">#</th>
        <th align="center">Column 1</th>
        <th align="center">Column 2</th>
        <th align="center">Column 3</th>
        <th align="center">Column 4</th>
    </tr>
    </thead>

    <tbody>

    <tr>
        <td>1</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>2</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>3</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>4</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>5</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>6</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>7</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>8</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>9</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>10</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    <tr>
        <td>11</td>
        <td align="center">Row value 1</td>
        <td align="center">Row value 2</td>
        <td align="center">Row value 3</td>
        <td align="center">Row value 4</td>
    </tr>

    </tbody>

</table>


<script type="text/javascript">
    $(document).ready(function(){
        $('#table_list').DataTable({
            "lengthMenu": [
                [10, 25, 50, -1], [10, 25, 50, "<?php echo ___("needs/allOf"); ?>"]
            ],
            responsive: true,
            "language":{"url":"<?php echo APP_URI; ?>/<?php echo ___("package/code"); ?>/datatable/lang.json"}
        });

    });
</script>
